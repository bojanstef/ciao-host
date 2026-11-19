//! Destination-owned delegation policy. Peers never enter the phone/shell allowlist.
use std::{
    collections::HashSet,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{Result, bail};
use iroh::EndpointId;
use parking_lot::Mutex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

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

/// The reserved `workspace_ids` entry that encodes [`GrantScope::All`].
///
/// Encoded inside the existing list, not as a new field, so a store or description holding an
/// all-projects grant still parses under 0.1.61 and older apps: there it is one unknown workspace
/// ID that admits nothing (fail closed), and an older app still sees a grant it can revoke. Real
/// workspace IDs are 32 hex characters, so this never collides with one.
pub(crate) const ALL_WORKSPACES: &str = "all";

/// Which destination workspaces a grant admits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GrantScope {
    /// Every workspace this host resolves by ID at request time, including ones that appear
    /// later: managed-session records plus discovered checkouts. Never a peer-supplied path.
    All,
    /// Exactly these workspace IDs.
    Selected(Vec<String>),
}

impl GrantScope {
    pub fn covers(&self, workspace_id: &str) -> bool {
        match self {
            Self::All => true,
            Self::Selected(ids) => ids.iter().any(|id| id == workspace_id),
        }
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        let Self::Selected(ids) = self else {
            return Ok(());
        };
        if ids.is_empty()
            || ids.len() > MAX_WORKSPACES
            || ids.iter().any(|id| !valid_id(id) || id == ALL_WORKSPACES)
            || ids.iter().collect::<HashSet<_>>().len() != ids.len()
        {
            return Err("invalid_scope");
        }
        Ok(())
    }
}

impl Serialize for GrantScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::All => [ALL_WORKSPACES].serialize(serializer),
            Self::Selected(ids) => ids.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for GrantScope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let ids = Vec::<String>::deserialize(deserializer)?;
        Ok(match ids.as_slice() {
            [only] if only == ALL_WORKSPACES => Self::All,
            _ => Self::Selected(ids),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Incoming {
    pub peer: Descriptor,
    pub grant_id: String,
    pub issuer: String,
    #[serde(rename = "workspace_ids")]
    pub scope: GrantScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Outgoing {
    pub peer: Descriptor,
    pub grant_id: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PeerAgent {
    #[default]
    Claude,
    Codex,
}

impl PeerAgent {
    fn is_default(&self) -> bool {
        *self == Self::Claude
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StartRecord {
    pub grant_id: String,
    pub request_id: String,
    pub workspace_id: String,
    #[serde(default, skip_serializing_if = "PeerAgent::is_default")]
    pub agent: PeerAgent,
    pub outcome: Option<crate::agent_protocol::LifecycleOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_request: Option<String>,
}

impl StartRecord {
    // A legacy daemon can read and replay this refusal. It never receives a Codex session ID.
    fn legacy_reservation(&self) -> Self {
        Self {
            agent: PeerAgent::Claude,
            stop_request: None,
            outcome: Some(crate::agent_protocol::LifecycleOutcome {
                v: crate::agent_protocol::AGENT_PROTOCOL_VERSION,
                command_id: command_id(&self.grant_id, &format!("start/{}", self.request_id)),
                state: "refused".into(),
                reason_code: Some("native_codex_required".into()),
                session_id: None,
                process_generation: None,
                deduplicated: None,
                resume_command: None,
            }),
            ..self.clone()
        }
    }

    fn is_codex_reservation(&self) -> bool {
        self.outcome.as_ref().and_then(|o| o.reason_code.as_deref())
            == Some("native_codex_required")
    }

    // A human can later pick up the same Codex thread under its stable Ciao session ID.
    pub fn includes_generation(&self, generation: u64) -> bool {
        self.agent == PeerAgent::Claude
            || self
                .outcome
                .as_ref()
                .and_then(|outcome| outcome.process_generation)
                == Some(generation)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Store {
    pub incoming: Vec<Incoming>,
    pub outgoing: Vec<Outgoing>,
    pub starts: Vec<StartRecord>,
}

impl Store {
    fn disk_records(&self) -> (Self, Vec<StartRecord>) {
        let mut authority = self.clone();
        let mut codex_receipts = Vec::new();
        for record in &mut authority.starts {
            if record.agent == PeerAgent::Codex {
                if record.outcome.is_some() {
                    codex_receipts.push(record.clone());
                }
                *record = record.legacy_reservation();
            }
        }
        (authority, codex_receipts)
    }

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
                || grant.scope.validate().is_err()
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
            if let Some(stop) = &claim.stop_request
                && (!valid_id(stop)
                    || claim.agent != PeerAgent::Codex
                    || !claim
                        .outcome
                        .as_ref()
                        .is_some_and(|o| o.state == "accepted"))
            {
                bail!("invalid_stop_claim");
            }
            if claim.agent == PeerAgent::Codex
                && claim.outcome.as_ref().is_some_and(|o| {
                    o.state == "accepted"
                        && (o.session_id.is_none() || o.process_generation.unwrap_or_default() == 0)
                })
            {
                bail!("invalid_codex_claim");
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
    outbound: Mutex<std::collections::HashMap<EndpointId, std::sync::Weak<tokio::sync::Mutex<()>>>>,
    pub connections: Mutex<std::collections::HashMap<String, iroh::endpoint::Connection>>,
}

pub(crate) fn codex_receipts_path(authority: &Path) -> PathBuf {
    authority.with_file_name("peer-codex-receipts.json")
}

fn load_private<T: serde::de::DeserializeOwned + Default>(path: &Path) -> Result<T> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(T::default()),
        result => result?,
    };
    validate_private_file(path)?;
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_STORE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STORE_BYTES {
        bail!("peer_store_too_large");
    }
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_private<T: Serialize>(path: &Path, value: &T) -> Result<(), &'static str> {
    let bytes = serde_json::to_vec(value).map_err(|_| "storage_failed")?;
    if bytes.len() as u64 > MAX_STORE_BYTES {
        return Err("peer_limit");
    }
    atomic_write_private(path, &bytes).map_err(|_| "storage_failed")
}

impl Peers {
    pub fn load(path: &Path) -> Result<Self> {
        let mut store: Store = load_private(path)?;
        store.validate()?;
        if store.starts.iter().any(StartRecord::is_codex_reservation) {
            let receipts: Vec<StartRecord> = load_private(&codex_receipts_path(path))?;
            if receipts.len() > MAX_STARTS {
                bail!("peer_limit");
            }
            for claim in store.starts.iter_mut().filter(|r| r.is_codex_reservation()) {
                let receipt = receipts.iter().find(|r| {
                    r.agent == PeerAgent::Codex
                        && r.grant_id == claim.grant_id
                        && r.request_id == claim.request_id
                        && r.workspace_id == claim.workspace_id
                });
                if let Some(receipt) = receipt {
                    *claim = receipt.clone();
                } else {
                    claim.agent = PeerAgent::Codex;
                    claim.outcome = None;
                }
            }
            store.validate()?;
        }
        Ok(Self {
            path: path.into(),
            store: Mutex::new(store),
            effects: tokio::sync::Mutex::new(()),
            outbound: Mutex::default(),
            connections: Mutex::new(Default::default()),
        })
    }

    /// A destination admits one connection from our endpoint. Concurrent local CLI requests
    /// queue for that destination while requests to a different host can proceed.
    pub fn outbound_lane(&self, id: EndpointId) -> std::sync::Arc<tokio::sync::Mutex<()>> {
        let mut lanes = self.outbound.lock();
        if let Some(lane) = lanes.get(&id).and_then(std::sync::Weak::upgrade) {
            return lane;
        }
        lanes.retain(|_, lane| lane.strong_count() > 0);
        let lane = std::sync::Arc::new(tokio::sync::Mutex::new(()));
        lanes.insert(id, std::sync::Arc::downgrade(&lane));
        lane
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
        // The legacy-readable grant and reservation are authoritative. Write them first. A
        // missing receipt leaves an ambiguous claim, and a receipt without a grant grants nothing.
        let (authority, receipts) = next.disk_records();
        let (old_authority, old_receipts) = guard.disk_records();
        if old_authority != authority {
            write_private(&self.path, &authority)?;
        }
        if receipts != old_receipts
            && let Err(error) = write_private(&codex_receipts_path(&self.path), &receipts)
        {
            // Once the authoritative grant is gone, its old receipts cannot grant access.
            // Finish revocation (including closing the connection) if only pruning failed.
            if old_authority != authority && receipts.iter().all(|r| old_receipts.contains(r)) {
                tracing::warn!(%error, "could not prune revoked Codex peer receipts");
            } else {
                return Err(error);
            }
        }
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

    /// The workspace in which `grant_id` started `session`, if it did.
    fn started(&self, grant_id: &str, session: &str) -> Option<StartRecord> {
        self.store
            .lock()
            .starts
            .iter()
            .find(|r| {
                r.grant_id == grant_id
                    && r.outcome.as_ref().is_some_and(|o| {
                        o.state == "accepted" && o.session_id.as_deref() == Some(session)
                    })
            })
            .cloned()
    }

    /// Whether `grant` started `session` in a workspace it still covers. Narrowing a grant's
    /// scope fences its sessions outside the new scope the way revocation fences all of them:
    /// the worker keeps running under the person's control, and the peer loses its handle.
    pub fn owned_start(&self, grant: &Incoming, session: &str) -> Option<StartRecord> {
        self.started(&grant.grant_id, session)
            .filter(|record| grant.scope.covers(&record.workspace_id))
    }

    /// Whether `grant` started `session` at all, whatever its scope is now. The live-worker
    /// limit counts these, so narrowing and widening again cannot reset it.
    pub fn launched(&self, grant: &Incoming, session: &str) -> bool {
        self.started(&grant.grant_id, session).is_some()
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

    /// Remove `endpoint`'s permission to use this host. This host's own link to that endpoint
    /// is the other direction and is untouched (see [`Self::forget`]).
    pub fn revoke(&self, endpoint: &str) -> Result<(), &'static str> {
        self.change(|s| {
            let revoked: HashSet<_> = s
                .incoming
                .iter()
                .filter(|g| g.peer.endpoint_id == endpoint)
                .map(|g| g.grant_id.clone())
                .collect();
            s.incoming.retain(|g| g.peer.endpoint_id != endpoint);
            s.starts.retain(|r| !revoked.contains(&r.grant_id));
            Ok(())
        })?;
        self.close(endpoint);
        Ok(())
    }

    /// Drop this host's remembered link to `endpoint`. It grants and revokes nothing: the
    /// destination owns that permission.
    pub fn forget(&self, endpoint: &str) -> Result<(), &'static str> {
        self.change(|s| {
            s.outgoing.retain(|g| g.peer.endpoint_id != endpoint);
            Ok(())
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Admin {
    Describe {},
    Grant {
        peer: Descriptor,
        #[serde(rename = "workspace_ids")]
        scope: GrantScope,
    },
    /// Change an existing grant's scope in place. The grant ID, its issuer and the source's
    /// remembered link are kept, so nothing has to be introduced again.
    Update {
        endpoint_id: String,
        #[serde(rename = "workspace_ids")]
        scope: GrantScope,
    },
    /// Store (or replace) this host's link to a destination.
    Remember {
        link: Outgoing,
    },
    /// Remove an incoming grant.
    Revoke {
        endpoint_id: String,
    },
    /// Remove this host's outgoing link.
    Forget {
        endpoint_id: String,
    },
}

/// Bumped when the phone-facing administration surface gains something an app must not offer to
/// an older host. 2: `update`, `forget`, all-projects scope, upserting `remember`, and a
/// one-direction `revoke`. Absent means 1.
pub(crate) const ADMIN_REVISION: u8 = 2;

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
        #[serde(default, skip_serializing_if = "PeerAgent::is_default")]
        agent: PeerAgent,
        request_id: String,
        workspace_id: String,
    },
    Snapshot {
        session_id: String,
    },
    Command {
        command: AgentCommand,
    },
    StopReceipt {
        session_id: String,
        request_id: String,
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
                ..
            } if valid_id(request_id) && valid_id(workspace_id) => {}
            Action::Snapshot { session_id } if valid_id(session_id) => {}
            Action::StopReceipt {
                session_id,
                request_id,
            } if valid_id(session_id) && valid_id(request_id) => {}
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
    fn peer_agent_selection_keeps_the_original_claude_wire_shape() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../protocol/fixtures/phase1/peer-admin-v1.json"
        ))
        .unwrap();
        let cases = &fixture["agent_starts"];
        for (name, expected) in [("default", PeerAgent::Claude), ("codex", PeerAgent::Codex)] {
            let request: Request = serde_json::from_value(cases[name].clone()).unwrap();
            assert!(matches!(request.action, Action::Start {agent, ..} if agent == expected));
            assert_eq!(serde_json::to_value(request).unwrap(), cases[name]);
        }
        assert!(serde_json::from_value::<Request>(cases["unknown"].clone()).is_err());
    }

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
    fn peer_shared_fixture_carries_scopes_edits_and_one_direction_removal() {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Envelope {
            v: u8,
            action: Admin,
        }
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../protocol/fixtures/phase1/peer-admin-v1.json"
        ))
        .unwrap();
        assert_eq!(fixture["admin_revision"], ADMIN_REVISION);
        let revision = &fixture["revision_2"];
        for (name, request) in revision["requests"].as_object().unwrap() {
            let envelope: Envelope = serde_json::from_value(request.clone()).unwrap();
            assert_eq!(envelope.v, 1);
            // Byte-for-byte the shape this host would itself send (CLI) and accept (phone).
            assert_eq!(
                serde_json::to_value(&envelope.action).unwrap(),
                request["action"],
                "{name}"
            );
            match (name.as_str(), envelope.action) {
                ("grant_all", Admin::Grant { scope, .. })
                | ("update_all", Admin::Update { scope, .. }) => {
                    assert_eq!(scope, GrantScope::All)
                }
                ("grant_selected", Admin::Grant { scope, .. })
                | ("update_selected", Admin::Update { scope, .. }) => {
                    assert_eq!(scope, GrantScope::Selected(vec!["workspace-alpha".into()]))
                }
                ("revoke", Admin::Revoke { .. }) | ("forget", Admin::Forget { .. }) => {}
                (name, action) => panic!("{name} decoded as {action:?}"),
            }
        }
        let result = &revision["response"]["result"];
        let incoming: Vec<Incoming> = serde_json::from_value(result["incoming"].clone()).unwrap();
        assert_eq!(
            incoming[0].scope,
            GrantScope::Selected(vec!["workspace-alpha".into()])
        );
        assert_eq!(incoming[1].scope, GrantScope::All);
        Store {
            incoming,
            outgoing: serde_json::from_value(result["outgoing"].clone()).unwrap(),
            starts: vec![],
        }
        .validate()
        .unwrap();
        assert_eq!(result["admin_revision"], ADMIN_REVISION);
        for ids in revision["invalid_scopes"].as_array().unwrap() {
            let scope: GrantScope = serde_json::from_value(ids.clone()).unwrap();
            assert!(scope.validate().is_err(), "must reject {ids}");
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
    fn peer_missing_or_leftover_codex_receipts_never_restore_authority() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("peers.json");
        let peers = Peers::load(&path).unwrap();
        let id = iroh::SecretKey::generate().public();
        let grant = Incoming {
            peer: Descriptor {
                endpoint_id: id.to_string(),
                name: "Source".into(),
            },
            grant_id: "grant".into(),
            issuer: id.to_string(),
            scope: GrantScope::All,
        };
        peers
            .change(|s| {
                s.incoming.push(grant.clone());
                s.starts.push(StartRecord {
                    grant_id: grant.grant_id.clone(),
                    request_id: "start".into(),
                    workspace_id: "workspace".into(),
                    agent: PeerAgent::Codex,
                    stop_request: None,
                    outcome: Some(
                        serde_json::from_value(serde_json::json!({
                            "v":1, "command_id":"start", "state":"accepted",
                            "session_id":"session", "process_generation":1
                        }))
                        .unwrap(),
                    ),
                });
                Ok(())
            })
            .unwrap();
        let receipts = codex_receipts_path(&path);
        let saved = temp.path().join("saved");
        fs::rename(&receipts, &saved).unwrap();
        let pending = Peers::load(&path).unwrap().snapshot().starts.remove(0);
        assert_eq!(pending.agent, PeerAgent::Codex);
        assert!(pending.outcome.is_none());

        // A failed cleanup must still finish the revocation that already reached disk.
        fs::create_dir(&receipts).unwrap();
        peers.revoke(&id.to_string()).unwrap();
        assert!(peers.incoming(id, None).is_none());
        fs::remove_dir(&receipts).unwrap();
        fs::rename(saved, receipts).unwrap();
        let cold = Peers::load(&path).unwrap();
        assert!(cold.incoming(id, None).is_none());
        assert!(cold.snapshot().starts.is_empty());
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
