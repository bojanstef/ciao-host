//! The restricted peer transport and phone-authorized introduction path (Spec 026).
use super::*;
use crate::{
    agent_protocol::{self, AgentCommand, AgentCommandKind},
    peers::{self, Action, Admin, Descriptor, Incoming, Outgoing, Request, StartRecord},
};
use serde::{Deserialize, Serialize};
use serde_json::json;

const DEADLINE: Duration = Duration::from_secs(75);

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    v: u8,
    result: Option<Value>,
    error: Option<String>,
}

fn reply(result: Result<Value, &'static str>) -> Reply {
    match result {
        Ok(result) => Reply {
            v: 1,
            result: Some(result),
            error: None,
        },
        Err(error) => Reply {
            v: 1,
            result: None,
            error: Some(error.into()),
        },
    }
}

async fn read_request<T: serde::de::DeserializeOwned>(
    recv: &mut iroh::endpoint::RecvStream,
    deadline: Duration,
) -> Result<T, &'static str> {
    timeout(deadline, async {
        let body = agent_protocol::read_agent_frame_within(recv, peers::MAX_REPLY_BYTES)
            .await
            .map_err(|_| "invalid_request")?;
        let value = serde_json::from_slice(&body).map_err(|_| "invalid_request")?;
        if recv
            .read(&mut [0_u8; 1])
            .await
            .map_err(|_| "invalid_request")?
            .is_some()
        {
            return Err("invalid_request");
        }
        Ok(value)
    })
    .await
    .map_err(|_| "timeout")?
}

pub(super) async fn admin_stream(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    issuer: EndpointId,
    state: &Arc<RuntimeState>,
) {
    let result = async {
        if !state.paired_devices.lock().contains(issuer) {
            return Err("authorization_denied");
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Envelope {
            v: u8,
            action: Admin,
        }
        let envelope: Envelope = read_request(recv, Duration::from_secs(10)).await?;
        if envelope.v != 1 {
            return Err("unsupported_version");
        }
        admin(envelope.action, Some(issuer), state).await
    };
    let result = timeout(DEADLINE, result).await.unwrap_or(Err("timeout"));
    let _ = agent_protocol::write_agent_frame_within(send, &reply(result), peers::MAX_REPLY_BYTES)
        .await;
    let _ = send.finish();
}

async fn admin(
    action: Admin,
    issuer: Option<EndpointId>,
    state: &Arc<RuntimeState>,
) -> Result<Value, &'static str> {
    if issuer.is_some_and(|id| !state.paired_devices.lock().contains(id)) {
        return Err("authorization_denied");
    }
    // Discovery does filesystem work. It must not hold the gate a revoke is waiting for.
    let projects = if matches!(action, Admin::Describe {} | Admin::Grant { .. }) {
        Some(state.managed_sessions.workspaces().await)
    } else {
        None
    };
    // Acquiring the effect gate precedes the final authorization check. Revocation cannot
    // race a delayed start/command, or a device unpair race a delayed introduction.
    let _effects = state.peers.effects.lock().await;
    if issuer.is_some_and(|id| !state.paired_devices.lock().contains(id)) {
        return Err("authorization_denied");
    }
    match action {
        Admin::Describe {} => {
            let store = state.peers.snapshot();
            description_result(state, store, projects.ok_or("internal_error")?)
        }
        Admin::Grant {
            peer,
            workspace_ids,
        } => {
            peer.validate().map_err(|_| "invalid_peer")?;
            if peer.endpoint_id == state.host_endpoint_id.to_string() {
                return Err("self_link");
            }
            let known = projects.ok_or("internal_error")?;
            if workspace_ids.is_empty()
                || workspace_ids.len() > peers::MAX_WORKSPACES
                || workspace_ids
                    .iter()
                    .any(|id| !known.workspaces.iter().any(|w| w.workspace_id == *id))
            {
                return Err("unknown_workspace");
            }
            let grant = Incoming {
                peer: peer.clone(),
                grant_id: format!("{:032x}", rand::random::<u128>()),
                issuer: issuer.unwrap_or(state.host_endpoint_id).to_string(),
                workspace_ids,
            };
            state.peers.change(|s| {
                if s.incoming
                    .iter()
                    .any(|g| g.peer.endpoint_id == peer.endpoint_id)
                {
                    return Err("already_linked");
                }
                if s.incoming.len() >= peers::MAX_PEERS {
                    return Err("peer_limit");
                }
                s.incoming.push(grant.clone());
                Ok(())
            })?;
            Ok(
                json!({"peer": Descriptor { endpoint_id: state.host_endpoint_id.to_string(), name: state.host_info.display_name.clone() }, "grant_id": grant.grant_id}),
            )
        }
        Admin::Remember { link } => {
            link.peer.validate().map_err(|_| "invalid_peer")?;
            if !peers::valid_id(&link.grant_id)
                || link.peer.endpoint_id == state.host_endpoint_id.to_string()
            {
                return Err("invalid_link");
            }
            state.peers.change(|s| {
                if s.outgoing
                    .iter()
                    .any(|g| g.peer.endpoint_id == link.peer.endpoint_id)
                {
                    return Err("already_linked");
                }
                if s.outgoing.len() >= peers::MAX_PEERS {
                    return Err("peer_limit");
                }
                s.outgoing.push(link);
                Ok(())
            })?;
            Ok(json!({"state":"accepted"}))
        }
        Admin::Revoke { endpoint_id } => {
            endpoint_id
                .parse::<EndpointId>()
                .map_err(|_| "invalid_peer")?;
            state.peers.revoke(&endpoint_id)?;
            Ok(json!({"state":"revoked"}))
        }
    }
}

fn description_result(
    state: &RuntimeState,
    store: peers::Store,
    projects: agent_protocol::AgentWorkspaceList,
) -> Result<Value, &'static str> {
    let mut incomplete = projects.scan_incomplete
        || projects.omitted_workspaces > 0
        || projects.workspaces.len() > peers::MAX_WORKSPACES;
    let mut workspaces: Vec<_> = projects
        .workspaces
        .into_iter()
        .take(peers::MAX_WORKSPACES)
        .collect();
    loop {
        let result = json!({
            "peer": Descriptor { endpoint_id: state.host_endpoint_id.to_string(), name: state.host_info.display_name.clone() },
            "incoming": &store.incoming, "outgoing": &store.outgoing,
            "workspaces": &workspaces, "scan_incomplete": incomplete,
        });
        if agent_protocol::encoded_frame_len(&crate::ipc::success_response(
            &"x".repeat(crate::ipc::MAX_IPC_REQUEST_ID_BYTES),
            result.clone(),
        )) <= crate::ipc::MAX_IPC_LINE
        {
            return Ok(result);
        }
        // All grants stay visible so large project labels cannot hide the Revoke control.
        if workspaces.pop().is_none() {
            return Err("response_too_large");
        }
        incomplete = true;
    }
}

pub(super) fn revoke_issuer(state: &Arc<RuntimeState>, issuer: &str) -> Result<(), &'static str> {
    let revoked: Vec<_> = state
        .peers
        .snapshot()
        .incoming
        .into_iter()
        .filter(|g| g.issuer == issuer)
        .map(|g| g.peer.endpoint_id)
        .collect();
    for id in revoked {
        state.peers.revoke(&id)?;
    }
    Ok(())
}

pub(super) async fn serve(connection: Connection, state: Arc<RuntimeState>) {
    let id = connection.remote_id();
    if state.peers.incoming(id, None).is_none() {
        connection.close(
            VarInt::from_u32(CONNECTION_AUTHORIZATION_DENIED),
            b"peer access denied",
        );
        return;
    }
    let key = id.to_string();
    {
        let _effects = state.peers.effects.lock().await;
        if state.peers.incoming(id, None).is_none() {
            connection.close(
                VarInt::from_u32(CONNECTION_AUTHORIZATION_DENIED),
                b"peer access denied",
            );
            return;
        }
        let mut connections = state.peers.connections.lock();
        if connections.contains_key(&key) || connections.len() >= peers::MAX_PEERS {
            connection.close(VarInt::from_u32(CONNECTION_BUSY), b"peer busy");
            return;
        }
        connections.insert(key.clone(), connection.clone());
    }
    // One finite request per connection. There are no long-lived peer subscriptions whose
    // revocation/overflow semantics could accidentally inherit the phone's authorization.
    if let Ok(Ok((mut send, mut recv))) =
        timeout(Duration::from_secs(10), connection.accept_bi()).await
    {
        let result = timeout(DEADLINE, async {
            let request: Request = read_request(&mut recv, Duration::from_secs(10)).await?;
            execute(id, request, &state).await
        })
        .await
        .unwrap_or(Err("timeout"));
        let _ = agent_protocol::write_agent_frame_within(
            &mut send,
            &reply(result),
            peers::MAX_REPLY_BYTES,
        )
        .await;
        let _ = send.finish();
        // Wait for the send to be acknowledged before closing the connection. This await is
        // bounded and cancellation does not undo an already recorded effect.
        let _ = timeout(Duration::from_secs(5), send.stopped()).await;
    }
    // A revoke may have removed this entry; avoid removing a newly admitted connection.
    let mut connections = state.peers.connections.lock();
    if connections
        .get(&key)
        .is_some_and(|c| c.stable_id() == connection.stable_id())
    {
        connections.remove(&key);
    }
    connection.close(VarInt::from_u32(0), b"peer request complete");
}

async fn execute(
    id: EndpointId,
    request: Request,
    state: &Arc<RuntimeState>,
) -> Result<Value, &'static str> {
    request.validate()?;
    let projects = if matches!(request.action, Action::Workspaces {}) {
        if state.peers.incoming(id, Some(&request.grant_id)).is_none() {
            return Err("authorization_denied");
        }
        Some(state.managed_sessions.workspaces().await)
    } else {
        None
    };
    let _effects = state.peers.effects.lock().await;
    let grant = state
        .peers
        .incoming(id, Some(&request.grant_id))
        .ok_or("authorization_denied")?;
    match request.action {
        Action::Workspaces {} => {
            let projects = projects.ok_or("internal_error")?;
            let selected: Vec<_> = projects
                .workspaces
                .into_iter()
                .filter(|w| grant.workspace_ids.contains(&w.workspace_id))
                .collect();
            Ok(
                json!({"workspaces":selected, "scan_incomplete":projects.scan_incomplete, "agent":"claude"}),
            )
        }
        Action::Start {
            request_id,
            workspace_id,
        } => {
            if !grant.workspace_ids.contains(&workspace_id) {
                return Err("authorization_denied");
            }
            let store = state.peers.snapshot();
            if let Some(record) = store
                .starts
                .iter()
                .find(|r| r.grant_id == grant.grant_id && r.request_id == request_id)
            {
                if record.workspace_id != workspace_id {
                    return Err("request_id_reused");
                }
                return record
                    .outcome
                    .as_ref()
                    .map(|o| json!(o))
                    .ok_or("outcome_unknown");
            }
            let live = state
                .managed_sessions
                .summaries()
                .into_iter()
                .filter(|s| {
                    s.presence == "live" && state.peers.owns(&grant.grant_id, &s.session_id)
                })
                .count()
                + store
                    .starts
                    .iter()
                    .filter(|r| r.grant_id == grant.grant_id && r.outcome.is_none())
                    .count();
            if live >= peers::MAX_LIVE {
                return Err("worker_limit");
            }
            state.peers.change(|s| {
                if s.starts.len() >= peers::MAX_STARTS {
                    return Err("request_limit");
                }
                s.starts.push(StartRecord {
                    grant_id: grant.grant_id.clone(),
                    request_id: request_id.clone(),
                    workspace_id: workspace_id.clone(),
                    outcome: None,
                });
                Ok(())
            })?;
            let command_id = peers::command_id(&grant.grant_id, &format!("start/{request_id}"));
            let outcome = state
                .managed_sessions
                .managed_start(&workspace_id, &command_id)
                .await;
            state.peers.change(|s| {
                let record = s
                    .starts
                    .iter_mut()
                    .find(|r| r.grant_id == grant.grant_id && r.request_id == request_id)
                    .ok_or("outcome_unknown")?;
                record.outcome = Some(outcome.clone());
                Ok(())
            })?;
            Ok(json!(outcome))
        }
        Action::Snapshot { session_id } => {
            if !state.peers.owns(&grant.grant_id, &session_id) {
                return Err("authorization_denied");
            }
            let snapshot = state
                .agent_sessions
                .snapshot(&session_id)
                .or_else(|| {
                    state
                        .managed_sessions
                        .stored_snapshot(&session_id, &HashSet::new())
                })
                .ok_or("session_unavailable")?;
            let snapshot = agent_protocol::fit_snapshot_with_envelope(snapshot, |s| {
                agent_protocol::encoded_frame_len(&crate::ipc::success_response(
                    &"x".repeat(crate::ipc::MAX_IPC_REQUEST_ID_BYTES),
                    json!(s),
                ))
            });
            Ok(json!(snapshot))
        }
        Action::Command { mut command } => {
            if !state.peers.owns(&grant.grant_id, &command.session_id) {
                return Err("authorization_denied");
            }
            command.command_id = peers::command_id(&grant.grant_id, &command.command_id);
            // This is automation, not evidence that the person is using the phone (Spec 025).
            Ok(json!(
                state.agent_sessions.submit_peer_command(command).await
            ))
        }
        Action::Stop {
            session_id,
            request_id,
            expected_generation,
        } => {
            if !state.peers.owns(&grant.grant_id, &session_id) {
                return Err("authorization_denied");
            }
            let outcome = state
                .managed_sessions
                .managed_stop(
                    &session_id,
                    expected_generation,
                    &peers::command_id(&grant.grant_id, &format!("stop/{request_id}")),
                )
                .await;
            Ok(json!(outcome))
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Local {
    Admin {
        action: Admin,
    },
    Call {
        host: String,
        action: Action,
    },
    Send {
        host: String,
        session_id: String,
        request_id: String,
        text: Option<String>,
    },
    Stop {
        host: String,
        session_id: String,
        request_id: String,
    },
}

pub(super) async fn ipc(
    body: Value,
    endpoint: &Endpoint,
    state: &Arc<RuntimeState>,
) -> Result<Value, &'static str> {
    match serde_json::from_value(body).map_err(|_| "invalid_request")? {
        Local::Admin { action } => admin(action, None, state).await,
        Local::Call { host, action } => call(&host, action, endpoint, state).await,
        Local::Send {
            host,
            session_id,
            request_id,
            text,
        } => {
            if !peers::valid_id(&request_id) {
                return Err("invalid_request");
            }
            let snapshot: agent_protocol::AgentSessionSnapshot = serde_json::from_value(
                call(
                    &host,
                    Action::Snapshot {
                        session_id: session_id.clone(),
                    },
                    endpoint,
                    state,
                )
                .await?,
            )
            .map_err(|_| "invalid_response")?;
            let kind = match text {
                Some(text) => AgentCommandKind::Prompt { text },
                None => AgentCommandKind::Interrupt,
            };
            let command = AgentCommand {
                v: 1,
                command_id: request_id,
                session_id,
                snapshot_epoch: snapshot.snapshot_epoch,
                expected_generation: snapshot.process_generation,
                expected_revision: Some(snapshot.revision),
                kind,
            };
            call(&host, Action::Command { command }, endpoint, state).await
        }
        Local::Stop {
            host,
            session_id,
            request_id,
        } => {
            let snapshot: agent_protocol::AgentSessionSnapshot = serde_json::from_value(
                call(
                    &host,
                    Action::Snapshot {
                        session_id: session_id.clone(),
                    },
                    endpoint,
                    state,
                )
                .await?,
            )
            .map_err(|_| "invalid_response")?;
            call(
                &host,
                Action::Stop {
                    session_id,
                    request_id,
                    expected_generation: snapshot.process_generation,
                },
                endpoint,
                state,
            )
            .await
        }
    }
}

async fn call(
    host: &str,
    action: Action,
    endpoint: &Endpoint,
    state: &Arc<RuntimeState>,
) -> Result<Value, &'static str> {
    if host.is_empty() || host.len() > 128 {
        return Err("invalid_peer");
    }
    let matches: Vec<Outgoing> = state
        .peers
        .snapshot()
        .outgoing
        .into_iter()
        .filter(|l| l.peer.name == host || l.peer.endpoint_id.starts_with(host))
        .collect();
    let [link] = matches.as_slice() else {
        return Err("unknown_or_ambiguous_peer");
    };
    let id: EndpointId = link.peer.endpoint_id.parse().map_err(|_| "invalid_peer")?;
    let request = Request {
        v: 1,
        grant_id: link.grant_id.clone(),
        action,
    };
    request.validate()?;
    let connection = timeout(Duration::from_secs(10), endpoint.connect(id, peers::ALPN))
        .await
        .map_err(|_| "peer_unreachable")?
        .map_err(connect_error)?;
    exchange(&connection, &request).await
}

fn connect_error(error: iroh::endpoint::ConnectError) -> &'static str {
    match error {
        iroh::endpoint::ConnectError::Connection { source, .. }
        | iroh::endpoint::ConnectError::Connecting {
            source: ConnectingError::ConnectionError { source, .. },
            ..
        } => close_error(Some(source)).unwrap_or("peer_unreachable"),
        _ => "peer_unreachable",
    }
}

fn close_error(error: Option<ConnectionError>) -> Option<&'static str> {
    match error {
        Some(ConnectionError::ApplicationClosed(close))
            if close.error_code == VarInt::from_u32(CONNECTION_AUTHORIZATION_DENIED) =>
        {
            Some("authorization_denied")
        }
        Some(ConnectionError::ApplicationClosed(close))
            if close.error_code == VarInt::from_u32(CONNECTION_BUSY) =>
        {
            Some("peer_busy")
        }
        _ => None,
    }
}

async fn exchange(connection: &Connection, request: &Request) -> Result<Value, &'static str> {
    let result = timeout(DEADLINE, async {
        let (mut send, mut recv) = connection.open_bi().await.map_err(|_| "connection_lost")?;
        agent_protocol::write_agent_frame(&mut send, request)
            .await
            .map_err(|_| "invalid_request")?;
        send.finish().map_err(|_| "connection_lost")?;
        let response: Reply = read_request(&mut recv, DEADLINE).await.map_err(|code| {
            if code == "invalid_request" {
                "invalid_response"
            } else {
                code
            }
        })?;
        if response.v != 1 {
            return Err("unsupported_version");
        }
        match (response.result, response.error) {
            (Some(result), None) => Ok(result),
            (None, Some(code)) => Err(remote_error(&code)),
            _ => Err("invalid_response"),
        }
    })
    .await
    .unwrap_or(Err("outcome_unknown"));
    let result = if result.is_err() {
        close_error(connection.close_reason()).map_or(result, Err)
    } else {
        result
    };
    connection.close(VarInt::from_u32(0), b"peer request complete");
    result
}

fn remote_error(code: &str) -> &'static str {
    match code {
        "authorization_denied" => "authorization_denied",
        "worker_limit" => "worker_limit",
        "request_limit" => "request_limit",
        "outcome_unknown" => "outcome_unknown",
        "request_id_reused" => "request_id_reused",
        "session_unavailable" => "session_unavailable",
        "unknown_workspace" => "unknown_workspace",
        _ => "peer_refused",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_protocol::{
        AgentCapabilities, CommandCapabilities, InteractionCapabilities, Observation, TurnState,
    };
    use crate::agent_session::NormalizedRegistration;
    use tempfile::TempDir;

    #[tokio::test]
    #[ignore = "isolated two-host simulator lab; requires CIAO_PEER_LAB_DIR and has a 15-minute lifetime"]
    async fn peer_simulator_lab() {
        let root =
            PathBuf::from(std::env::var("CIAO_PEER_LAB_DIR").expect("explicit lab directory"));
        assert!(
            root.is_absolute()
                && root
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("ciao-peer-lab-")
        );
        crate::storage::ensure_private_directory(&root).unwrap();
        let mut endpoints = Vec::new();
        let mut tasks = Vec::new();
        let mut sockets = serde_json::Map::new();
        for (name, project) in [
            ("Source Computer", "frontend"),
            ("Build Computer", "backend"),
        ] {
            let home = root.join(project);
            let paths = crate::storage::CiaoPaths::for_home(&home);
            let identity = crate::identity::create_or_load_identity(&paths)
                .unwrap()
                .identity;
            fs::create_dir_all(home.join(project).join(".git")).unwrap();
            let mut state =
                super::super::tests::test_state(identity.endpoint_id, &paths.paired_devices_file);
            Arc::get_mut(&mut state).unwrap().host_info.display_name = name.into();
            Arc::get_mut(&mut state).unwrap().managed_sessions = ManagedSessionDirectory::load(
                &paths.agent_managed_file,
                &home,
                ManagedLauncher::Fake(crate::managed_session::fake::FakeLauncher::default()),
            )
            .unwrap();
            let mut builder = Endpoint::builder(presets::N0)
                .secret_key(identity.secret_key)
                .alpns(vec![
                    PAIRING_ALPN.to_vec(),
                    HOST_ALPN.to_vec(),
                    peers::ALPN.to_vec(),
                ])
                .transport_config(host_transport_config());
            if let Some(map) = crate::relay::configured_map().unwrap() {
                builder = builder.relay_mode(RelayMode::Custom(map));
            }
            let endpoint = builder.bind().await.unwrap();
            let listener = super::super::bind_control_socket(&paths).await.unwrap();
            tasks.push(tokio::spawn(super::super::serve_ipc(
                listener,
                endpoint.clone(),
                state.clone(),
            )));
            tasks.push(tokio::spawn(super::super::serve_iroh(
                endpoint.clone(),
                state.clone(),
            )));
            let monitor_endpoint = endpoint.clone();
            tasks.push(tokio::spawn(async move {
                super::super::monitor_home_relay(monitor_endpoint, state).await;
                Ok(())
            }));
            sockets.insert(project.into(), json!(paths.socket_file));
            endpoints.push(endpoint);
        }
        crate::storage::atomic_write_private(
            &root.join("lab.json"),
            &serde_json::to_vec(&sockets).unwrap(),
        )
        .unwrap();
        println!("isolated peer lab ready");
        tokio::time::sleep(Duration::from_secs(900)).await;
        for task in tasks {
            task.abort();
        }
        for endpoint in endpoints {
            endpoint.close().await;
        }
    }

    async fn fixture() -> (TempDir, Arc<RuntimeState>, EndpointId, Vec<String>, String) {
        let temp = tempfile::tempdir().unwrap();
        for name in ["alpha", "beta"] {
            fs::create_dir_all(temp.path().join(name).join(".git")).unwrap();
        }
        let state = super::super::tests::test_state(
            iroh::SecretKey::generate().public(),
            &temp.path().join("paired.json"),
        );
        let projects = state.managed_sessions.workspaces().await;
        assert_eq!(
            projects.workspaces.len(),
            2,
            "the test must have two real selectable workspaces"
        );
        let ids = projects
            .workspaces
            .into_iter()
            .map(|w| w.workspace_id)
            .collect::<Vec<_>>();
        let source = iroh::SecretKey::generate().public();
        let link = admin(
            Admin::Grant {
                peer: Descriptor {
                    endpoint_id: source.to_string(),
                    name: "Source".into(),
                },
                workspace_ids: ids.clone(),
            },
            None,
            &state,
        )
        .await
        .unwrap();
        let grant = link["grant_id"].as_str().unwrap().to_owned();
        (temp, state, source, ids, grant)
    }

    fn req(grant: &str, action: Action) -> Request {
        Request {
            v: 1,
            grant_id: grant.into(),
            action,
        }
    }

    async fn start(
        state: &Arc<RuntimeState>,
        source: EndpointId,
        grant: &str,
        id: &str,
        workspace: &str,
    ) -> Value {
        execute(
            source,
            req(
                grant,
                Action::Start {
                    request_id: id.into(),
                    workspace_id: workspace.into(),
                },
            ),
            state,
        )
        .await
        .unwrap()
    }

    async fn register(
        state: &Arc<RuntimeState>,
        session: &str,
    ) -> tokio::sync::mpsc::Receiver<crate::agent_session::BridgeCommandEnvelope> {
        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        let registration = NormalizedRegistration {
            terminal_binding: None,
            history_boundary: None,
            upstream_identity: session.into(),
            process_nonce: "fixture-worker".into(),
            process_id: std::process::id(),
            adapter_family: "Fixture".into(),
            adapter_version: "1.0.0".into(),
            topology: "managed".into(),
            compatible: true,
            version_state: "grounded".into(),
            tested_version: "1.0.0".into(),
            workspace_display: "Alpha".into(),
            workspace_path: None,
            observation: Observation {
                coverage: "authoritative".into(),
                reason_code: "worker_stream".into(),
                last_authoritative_at: None,
            },
            turn: TurnState::Idle,
            capabilities: AgentCapabilities {
                history: "live_tail".into(),
                commands: CommandCapabilities {
                    prompt: true,
                    steer: false,
                    follow_up: false,
                    interrupt: true,
                    permission_mode: false,
                    model: false,
                    effort: false,
                },
                interactions: InteractionCapabilities::none(),
                pending_rehydration: "current_process".into(),
                terminal_continuity: "unavailable".into(),
            },
            control_owner: "none".into(),
        };
        let registered = state
            .agent_sessions
            .register(registration, sender)
            .await
            .unwrap();
        assert_eq!(registered.session_id, session);
        receiver
    }

    #[tokio::test]
    async fn peer_authority_scopes_workspace_session_replay_and_worker_limit() {
        let (_temp, state, source, ids, grant) = fixture().await;
        let other = iroh::SecretKey::generate().public();
        assert_eq!(
            execute(other, req(&grant, Action::Workspaces {}), &state)
                .await
                .unwrap_err(),
            "authorization_denied"
        );
        assert_eq!(
            execute(
                source,
                req(
                    &grant,
                    Action::Start {
                        request_id: "bad-workspace".into(),
                        workspace_id: "ungranted".into()
                    }
                ),
                &state
            )
            .await
            .unwrap_err(),
            "authorization_denied"
        );
        let first = start(&state, source, &grant, "first", &ids[0]).await;
        assert_eq!(first["state"], "accepted");
        let sid = first["session_id"].as_str().unwrap().to_owned();
        assert_eq!(start(&state, source, &grant, "first", &ids[0]).await, first);
        assert_eq!(
            state.managed_sessions.live_count(),
            1,
            "retry must not spawn another worker"
        );
        assert_eq!(
            execute(
                source,
                req(
                    &grant,
                    Action::Start {
                        request_id: "first".into(),
                        workspace_id: ids[1].clone()
                    }
                ),
                &state
            )
            .await
            .unwrap_err(),
            "request_id_reused"
        );
        assert_eq!(
            execute(
                source,
                req(
                    &grant,
                    Action::Snapshot {
                        session_id: "someone-elses-session".into()
                    }
                ),
                &state
            )
            .await
            .unwrap_err(),
            "authorization_denied"
        );
        let mut receiver = register(&state, &sid).await;
        let snapshot = execute(
            source,
            req(
                &grant,
                Action::Snapshot {
                    session_id: sid.clone(),
                },
            ),
            &state,
        )
        .await
        .unwrap();
        let command = AgentCommand {
            v: 1,
            command_id: "turn-one".into(),
            session_id: sid,
            snapshot_epoch: snapshot["snapshot_epoch"].as_u64().unwrap(),
            expected_generation: snapshot["process_generation"].as_u64().unwrap(),
            expected_revision: None,
            kind: AgentCommandKind::Prompt {
                text: "Synthetic task".into(),
            },
        };
        let receipt = execute(
            source,
            req(
                &grant,
                Action::Command {
                    command: command.clone(),
                },
            ),
            &state,
        )
        .await
        .unwrap();
        assert_eq!(receipt["state"], "sending");
        let delivered = receiver.try_recv().unwrap();
        assert_eq!(delivered.command.kind, command.kind);
        assert_ne!(
            delivered.command.command_id, "turn-one",
            "wire IDs must not collide with phone receipts"
        );
        execute(source, req(&grant, Action::Command { command }), &state)
            .await
            .unwrap();
        assert!(
            receiver.try_recv().is_err(),
            "command replay must not reach the worker twice"
        );
        start(&state, source, &grant, "second", &ids[1]).await;
        assert_eq!(
            execute(
                source,
                req(
                    &grant,
                    Action::Start {
                        request_id: "third".into(),
                        workspace_id: ids[0].clone()
                    }
                ),
                &state
            )
            .await
            .unwrap_err(),
            "worker_limit"
        );
    }

    #[tokio::test]
    async fn peer_revocation_and_regrant_never_restore_old_session_access() {
        let (_temp, state, source, ids, grant) = fixture().await;
        let started = start(&state, source, &grant, "first", &ids[0]).await;
        let session_id = started["session_id"].as_str().unwrap().to_owned();
        admin(
            Admin::Revoke {
                endpoint_id: source.to_string(),
            },
            None,
            &state,
        )
        .await
        .unwrap();
        assert_eq!(
            state.managed_sessions.live_count(),
            1,
            "revocation does not silently stop work"
        );
        assert_eq!(
            execute(source, req(&grant, Action::Workspaces {}), &state)
                .await
                .unwrap_err(),
            "authorization_denied"
        );
        let link = admin(
            Admin::Grant {
                peer: Descriptor {
                    endpoint_id: source.to_string(),
                    name: "Source".into(),
                },
                workspace_ids: ids,
            },
            None,
            &state,
        )
        .await
        .unwrap();
        let new_grant = link["grant_id"].as_str().unwrap();
        assert_ne!(new_grant, grant);
        assert_eq!(
            execute(
                source,
                req(new_grant, Action::Snapshot { session_id }),
                &state
            )
            .await
            .unwrap_err(),
            "authorization_denied"
        );
    }

    #[tokio::test]
    async fn peer_interrupted_start_is_durable_and_never_relaunched() {
        let (temp, state, source, ids, grant) = fixture().await;
        state
            .peers
            .change(|s| {
                s.starts.push(StartRecord {
                    grant_id: grant.clone(),
                    request_id: "interrupted".into(),
                    workspace_id: ids[0].clone(),
                    outcome: None,
                });
                Ok(())
            })
            .unwrap();
        let restarted = super::super::tests::test_state(
            state.host_endpoint_id,
            &temp.path().join("paired.json"),
        );
        assert_eq!(
            execute(
                source,
                req(
                    &grant,
                    Action::Start {
                        request_id: "interrupted".into(),
                        workspace_id: ids[0].clone()
                    }
                ),
                &restarted
            )
            .await
            .unwrap_err(),
            "outcome_unknown"
        );
        assert_eq!(restarted.managed_sessions.live_count(), 0);
    }

    #[tokio::test]
    async fn peer_issuer_unpair_and_delayed_administration_are_fenced() {
        let (_temp, state, source, ids, _grant) = fixture().await;
        let phone = iroh::SecretKey::generate().public();
        state
            .peers
            .change(|s| {
                s.incoming[0].issuer = phone.to_string();
                Ok(())
            })
            .unwrap();
        state
            .paired_devices
            .lock()
            .upsert(phone, 1, &[7; 32], &[8; 32])
            .unwrap();
        let endpoint = Endpoint::builder(presets::N0DisableRelay)
            .bind()
            .await
            .unwrap();
        super::super::process_ipc_operation(
            IpcOperation::Unpair {
                endpoint_id: phone.to_string(),
            },
            &endpoint,
            &state,
        )
        .await
        .unwrap();
        assert!(state.peers.incoming(source, None).is_none());
        assert_eq!(
            admin(
                Admin::Grant {
                    peer: Descriptor {
                        endpoint_id: source.to_string(),
                        name: "Source".into()
                    },
                    workspace_ids: ids
                },
                Some(phone),
                &state
            )
            .await
            .unwrap_err(),
            "authorization_denied"
        );
        endpoint.close().await;
    }

    #[tokio::test]
    async fn peer_connection_rejects_unknown_identity_before_decoding_and_has_no_phone_authority() {
        let temp = tempfile::tempdir().unwrap();
        let host = Endpoint::builder(presets::N0DisableRelay)
            .alpns(vec![peers::ALPN.to_vec(), HOST_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let client = Endpoint::builder(presets::N0DisableRelay)
            .bind()
            .await
            .unwrap();
        let state = super::super::tests::test_state(host.id(), &temp.path().join("paired.json"));
        for alpn in [peers::ALPN, HOST_ALPN] {
            let server = tokio::spawn({
                let host = host.clone();
                let state = state.clone();
                async move {
                    let connection = host.accept().await.unwrap().await.unwrap();
                    super::super::handle_authenticated_connection(connection, state).await;
                }
            });
            let connection = client.connect(host.addr(), alpn).await.unwrap();
            timeout(Duration::from_secs(3), connection.closed())
                .await
                .unwrap();
            server.await.unwrap();
            assert_eq!(state.decoded_host_prefaces.load(Ordering::Relaxed), 0);
            // Even an admitted peer remains absent from the phone allowlist.
            state
                .peers
                .change(|s| {
                    s.incoming = vec![Incoming {
                        peer: Descriptor {
                            endpoint_id: client.id().to_string(),
                            name: "Source".into(),
                        },
                        grant_id: "fixture-grant".into(),
                        issuer: host.id().to_string(),
                        workspace_ids: vec!["workspace".into()],
                    }];
                    Ok(())
                })
                .unwrap();
        }
        assert!(!state.paired_devices.lock().contains(client.id()));
        client.close().await;
        host.close().await;
    }

    #[tokio::test]
    async fn peer_real_iroh_request_launch_snapshot_and_revocation() {
        let (_temp, state, source, ids, grant) = fixture().await;
        // A separate endpoint supplies the actual authenticated identity. No relay, model,
        // production daemon, or owner's terminal participates in this transport rehearsal.
        let client = Endpoint::builder(presets::N0DisableRelay)
            .bind()
            .await
            .unwrap();
        let host = Endpoint::builder(presets::N0DisableRelay)
            .alpns(vec![peers::ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        state
            .peers
            .change(|s| {
                s.incoming[0].peer.endpoint_id = client.id().to_string();
                Ok(())
            })
            .unwrap();
        assert_ne!(source, client.id());
        async fn exchange(
            host: &Endpoint,
            client: &Endpoint,
            state: &Arc<RuntimeState>,
            request: Request,
        ) -> Reply {
            let server = tokio::spawn({
                let host = host.clone();
                let state = state.clone();
                async move {
                    let connection = host.accept().await.unwrap().await.unwrap();
                    serve(connection, state).await;
                }
            });
            let connection = client.connect(host.addr(), peers::ALPN).await.unwrap();
            let (mut send, mut recv) = connection.open_bi().await.unwrap();
            agent_protocol::write_agent_frame(&mut send, &request)
                .await
                .unwrap();
            send.finish().unwrap();
            let response = read_request(&mut recv, Duration::from_secs(10))
                .await
                .unwrap();
            connection.close(VarInt::from_u32(0), b"test complete");
            server.await.unwrap();
            response
        }
        let response = exchange(
            &host,
            &client,
            &state,
            req(
                &grant,
                Action::Start {
                    request_id: "network-start".into(),
                    workspace_id: ids[0].clone(),
                },
            ),
        )
        .await;
        assert!(response.error.is_none());
        let sid = response.result.unwrap()["session_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let _receiver = register(&state, &sid).await;
        let response = exchange(
            &host,
            &client,
            &state,
            req(&grant, Action::Snapshot { session_id: sid }),
        )
        .await;
        assert_eq!(response.result.unwrap()["presence"], "live");
        admin(
            Admin::Revoke {
                endpoint_id: client.id().to_string(),
            },
            None,
            &state,
        )
        .await
        .unwrap();
        assert!(state.peers.incoming(client.id(), None).is_none());
        client.close().await;
        host.close().await;
    }

    #[tokio::test]
    async fn peer_revocation_closes_an_admitted_connection_before_another_request() {
        let (_temp, mut state, _source, _ids, _grant) = fixture().await;
        let client = Endpoint::builder(presets::N0DisableRelay)
            .bind()
            .await
            .unwrap();
        let host = Endpoint::builder(presets::N0DisableRelay)
            .alpns(vec![peers::ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        Arc::get_mut(&mut state).unwrap().host_endpoint_id = host.id();
        state
            .peers
            .change(|s| {
                s.incoming[0].peer.endpoint_id = client.id().to_string();
                Ok(())
            })
            .unwrap();
        let server = tokio::spawn({
            let host = host.clone();
            let state = state.clone();
            async move {
                serve(host.accept().await.unwrap().await.unwrap(), state).await;
            }
        });
        let connection = client.connect(host.addr(), peers::ALPN).await.unwrap();
        timeout(Duration::from_secs(3), async {
            while state.peers.connections.lock().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        admin(
            Admin::Revoke {
                endpoint_id: client.id().to_string(),
            },
            None,
            &state,
        )
        .await
        .unwrap();
        timeout(Duration::from_secs(3), connection.closed())
            .await
            .unwrap();
        timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
        assert!(state.peers.connections.lock().is_empty());
        client.close().await;
        host.close().await;
    }

    #[tokio::test]
    async fn peer_caller_reports_authorization_denied_when_the_destination_rejects_before_decoding()
    {
        let temp = tempfile::tempdir().unwrap();
        let host = Endpoint::builder(presets::N0DisableRelay)
            .alpns(vec![peers::ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let client = Endpoint::builder(presets::N0DisableRelay)
            .bind()
            .await
            .unwrap();
        let state = super::super::tests::test_state(host.id(), &temp.path().join("paired.json"));
        for _ in 0..3 {
            let server = tokio::spawn({
                let host = host.clone();
                let state = state.clone();
                async move {
                    serve(host.accept().await.unwrap().await.unwrap(), state).await;
                }
            });
            let result = match client.connect(host.addr(), peers::ALPN).await {
                Ok(connection) => {
                    exchange(&connection, &req("revoked-grant", Action::Workspaces {})).await
                }
                Err(error) => Err(connect_error(error)),
            };
            assert_eq!(result.unwrap_err(), "authorization_denied");
            server.await.unwrap();
        }
        client.close().await;
        host.close().await;
    }

    #[test]
    fn peer_snapshots_account_for_the_local_ipc_envelope_without_losing_truncation_metadata() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../protocol/fixtures/phase4/agent-session-v1.json"
        ))
        .unwrap();
        let mut snapshot: agent_protocol::AgentSessionSnapshot =
            serde_json::from_value(fixture["snapshot"].clone()).unwrap();
        let mut entry = snapshot
            .timeline_window
            .entries
            .iter()
            .find(|e| matches!(e.body, agent_protocol::TimelineBody::Text { .. }))
            .unwrap()
            .clone();
        entry.body = agent_protocol::TimelineBody::Text {
            text: "quoted\"content\n".repeat(1024),
        };
        entry.truncation = agent_protocol::Truncation {
            truncated: false,
            reason_code: None,
            original_bytes: None,
        };
        snapshot.timeline_window.entries = (0..8)
            .map(|i| {
                let mut e = entry.clone();
                e.sequence = i + 1;
                e.entry_id = format!("entry-{i}");
                e
            })
            .collect();
        snapshot.timeline_window.oldest_sequence = Some(1);
        snapshot.timeline_window.newest_sequence = Some(8);
        snapshot.validate().unwrap();
        assert!(
            agent_protocol::encoded_frame_len(&crate::ipc::success_response(
                &"x".repeat(128),
                json!(snapshot)
            )) > crate::ipc::MAX_IPC_LINE,
            "input must exceed the real local transport bound"
        );
        let fitted = agent_protocol::fit_snapshot_with_envelope(snapshot, |s| {
            agent_protocol::encoded_frame_len(&crate::ipc::success_response(
                &"x".repeat(128),
                json!(s),
            ))
        });
        fitted.validate().unwrap();
        assert!(fitted.timeline_window.has_older);
        assert_eq!(fitted.timeline_window.entries.last().unwrap().sequence, 8);
        assert!(
            agent_protocol::encoded_frame_len(&crate::ipc::success_response(
                &"x".repeat(128),
                json!(fitted)
            )) <= crate::ipc::MAX_IPC_LINE
        );
    }

    #[tokio::test]
    async fn peer_large_project_labels_never_hide_permissions_or_overflow_administration() {
        let (_temp, state, _source, _ids, _grant) = fixture().await;
        let workspace_ids: Vec<_> = (0..peers::MAX_WORKSPACES)
            .map(|i| format!("{i:064}"))
            .collect();
        let mut store = peers::Store::default();
        for i in 0..peers::MAX_PEERS {
            let peer = Descriptor {
                endpoint_id: iroh::SecretKey::generate().public().to_string(),
                name: "\"".repeat(128),
            };
            store.incoming.push(Incoming {
                peer: peer.clone(),
                grant_id: format!("grant-{i}"),
                issuer: state.host_endpoint_id.to_string(),
                workspace_ids: workspace_ids.clone(),
            });
            store.outgoing.push(Outgoing {
                peer,
                grant_id: format!("outgoing-{i}"),
            });
        }
        let projects = agent_protocol::AgentWorkspaceList {
            v: 1,
            message_type: "agent_workspace_list".into(),
            workspaces: workspace_ids
                .into_iter()
                .map(|workspace_id| agent_protocol::WorkspaceDescriptor {
                    workspace_id,
                    display_label: "\u{1}".repeat(agent_protocol::MAX_WORKSPACE_LABEL_BYTES),
                })
                .collect(),
            omitted_workspaces: 0,
            scan_incomplete: false,
        };
        projects.validate().unwrap();
        let original = json!({"peer":Descriptor {endpoint_id:state.host_endpoint_id.to_string(),name:state.host_info.display_name.clone()},"incoming":&store.incoming,"outgoing":&store.outgoing,"workspaces":&projects.workspaces,"scan_incomplete":false});
        assert!(
            agent_protocol::encoded_frame_len(&crate::ipc::success_response(
                &"x".repeat(crate::ipc::MAX_IPC_REQUEST_ID_BYTES),
                original
            )) > crate::ipc::MAX_IPC_LINE
        );
        let result = description_result(&state, store, projects).unwrap();
        assert_eq!(result["incoming"].as_array().unwrap().len(), 16);
        assert_eq!(result["outgoing"].as_array().unwrap().len(), 16);
        assert_eq!(result["scan_incomplete"], true);
        assert!(
            agent_protocol::encoded_frame_len(&crate::ipc::success_response(
                &"x".repeat(crate::ipc::MAX_IPC_REQUEST_ID_BYTES),
                result
            )) <= crate::ipc::MAX_IPC_LINE
        );
    }
}
