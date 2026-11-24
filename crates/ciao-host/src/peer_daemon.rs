//! The restricted peer transport and phone-authorized introduction path (Spec 026).
use super::*;
use crate::{
    agent_protocol::{self, AgentCommand, AgentCommandKind, LifecycleOutcome},
    peers::{
        self, Action, Admin, AdmissionRefused, Descriptor, FollowMode, GrantScope, Incoming,
        Outgoing, PeerAgent, PeerProtocol, Request, SnapshotVersion, SourceBudget, StartRecord,
    },
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
    let projects = if matches!(
        action,
        Admin::Describe {} | Admin::Grant { .. } | Admin::Update { .. }
    ) {
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
        Admin::Grant { peer, scope } => {
            peer.validate().map_err(|_| "invalid_peer")?;
            if peer.endpoint_id == state.host_endpoint_id.to_string() {
                return Err("self_link");
            }
            scope.validate().map_err(|_| "unknown_workspace")?;
            let known = projects.ok_or("internal_error")?;
            if let GrantScope::Selected(ids) = &scope
                && ids
                    .iter()
                    .any(|id| !known.workspaces.iter().any(|w| w.workspace_id == *id))
            {
                return Err("unknown_workspace");
            }
            let grant = Incoming {
                peer: peer.clone(),
                grant_id: format!("{:032x}", rand::random::<u128>()),
                issuer: issuer.unwrap_or(state.host_endpoint_id).to_string(),
                scope,
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
        Admin::Update { endpoint_id, scope } => {
            endpoint_id
                .parse::<EndpointId>()
                .map_err(|_| "invalid_peer")?;
            scope.validate().map_err(|_| "unknown_workspace")?;
            let known = projects.ok_or("internal_error")?;
            state.peers.change(|s| {
                let grant = s
                    .incoming
                    .iter_mut()
                    .find(|g| g.peer.endpoint_id == endpoint_id)
                    .ok_or("not_linked")?;
                // An ID the grant already holds stays acceptable even when discovery no longer
                // lists it (a moved checkout, a list cut at its cap). Otherwise re-saving an
                // unchanged selection would be refused, the bug this operation exists to fix.
                let held = |id: &String| matches!(&grant.scope, GrantScope::Selected(old) if old.contains(id));
                if let GrantScope::Selected(ids) = &scope
                    && ids.iter().any(|id| {
                        !held(id) && !known.workspaces.iter().any(|w| w.workspace_id == *id)
                    })
                {
                    return Err("unknown_workspace");
                }
                grant.scope = scope;
                Ok(())
            })?;
            Ok(json!({"state":"updated"}))
        }
        Admin::Remember { link } => {
            link.peer.validate().map_err(|_| "invalid_peer")?;
            if !peers::valid_id(&link.grant_id)
                || link.peer.endpoint_id == state.host_endpoint_id.to_string()
            {
                return Err("invalid_link");
            }
            let destination = link.peer.endpoint_id.clone();
            state.peers.change(|s| {
                // Replace, not refuse: the phone has just obtained this grant from the
                // destination, so an older link here is stale (revoked, or from a grant that
                // was replaced) and refusing it left the pair impossible to link again.
                s.outgoing
                    .retain(|g| g.peer.endpoint_id != link.peer.endpoint_id);
                if s.outgoing.len() >= peers::MAX_PEERS {
                    return Err("peer_limit");
                }
                s.outgoing.push(link);
                Ok(())
            })?;
            state.peers.outbound.discard(&destination);
            Ok(json!({"state":"accepted"}))
        }
        Admin::Revoke { endpoint_id } => {
            endpoint_id
                .parse::<EndpointId>()
                .map_err(|_| "invalid_peer")?;
            state.peers.revoke(&endpoint_id)?;
            Ok(json!({"state":"revoked"}))
        }
        Admin::Forget { endpoint_id } => {
            endpoint_id
                .parse::<EndpointId>()
                .map_err(|_| "invalid_peer")?;
            state.peers.forget(&endpoint_id)?;
            Ok(json!({"state":"forgotten"}))
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
    // Projects a grant names lead, so the cap and the size fitting below cut unselected
    // projects first and the phone can label what it is about to edit. Stable otherwise.
    let mut workspaces = projects.workspaces;
    workspaces.sort_by_key(|w| {
        !store.incoming.iter().any(|g| match &g.scope {
            GrantScope::Selected(ids) => ids.contains(&w.workspace_id),
            GrantScope::All => false,
        })
    });
    workspaces.truncate(peers::MAX_WORKSPACES);
    loop {
        let result = json!({
            "peer": Descriptor { endpoint_id: state.host_endpoint_id.to_string(), name: state.host_info.display_name.clone() },
            "incoming": &store.incoming, "outgoing": &store.outgoing,
            "workspaces": &workspaces, "scan_incomplete": incomplete,
            "admin_revision": peers::ADMIN_REVISION,
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
    serve_within(connection, state, peers::INBOUND_IDLE).await;
}

async fn serve_within(connection: Connection, state: Arc<RuntimeState>, idle: Duration) {
    let Some(protocol) = PeerProtocol::negotiated(connection.alpn()) else {
        connection.close(
            VarInt::from_u32(CONNECTION_PROTOCOL_VIOLATION),
            b"peer protocol violation",
        );
        return;
    };
    let id = connection.remote_id();
    if state.peers.incoming(id, None).is_none() {
        connection.close(
            VarInt::from_u32(CONNECTION_AUTHORIZATION_DENIED),
            b"peer access denied",
        );
        return;
    }
    let key = id.to_string();
    let budget = {
        let _effects = state.peers.effects.lock().await;
        if state.peers.incoming(id, None).is_none() {
            connection.close(
                VarInt::from_u32(CONNECTION_AUTHORIZATION_DENIED),
                b"peer access denied",
            );
            return;
        }
        match state.peers.admit(&key, &connection, protocol) {
            Ok(budget) => budget,
            Err(AdmissionRefused::Busy) => {
                connection.close(VarInt::from_u32(CONNECTION_BUSY), b"peer busy");
                return;
            }
        }
    };
    match protocol {
        // One request per connection, as every 0.1.66 source expects.
        PeerProtocol::SingleRequest => {
            if let Ok(Ok((send, recv))) =
                timeout(Duration::from_secs(10), connection.accept_bi()).await
            {
                answer(send, recv, id, &state, None).await;
            }
        }
        // Each request is a finite exchange on its own stream, with the grant rechecked as for
        // a single request. Nothing a request starts outlives its reply.
        PeerProtocol::Streams => serve_streams(&connection, id, &budget, &state, idle).await,
    }
    // A revoke may have removed this entry; avoid removing a newly admitted connection.
    state.peers.release(&key, &connection);
    connection.close(VarInt::from_u32(0), b"peer request complete");
}

/// Accept requests on a kept connection, each on its own stream, until it closes or idles.
async fn serve_streams(
    connection: &Connection,
    id: EndpointId,
    budget: &SourceBudget,
    state: &Arc<RuntimeState>,
    idle: Duration,
) {
    let mut requests = tokio::task::JoinSet::new();
    loop {
        let (send, recv) = tokio::select! {
            biased;
            accepted = connection.accept_bi() => match accepted {
                Ok(streams) => streams,
                Err(_) => break,
            },
            Some(_) = requests.join_next(), if !requests.is_empty() => continue,
            // Every accepted request has been answered and acknowledged by now.
            () = tokio::time::sleep(idle), if requests.is_empty() => {
                connection.close(VarInt::from_u32(0), b"peer idle");
                break;
            }
        };
        // The next stream waits here for one of the source's request slots, so a source
        // cannot queue work on this host however many streams or connections it opens.
        let slot = tokio::select! {
            slot = budget.requests.clone().acquire_owned() => match slot {
                Ok(slot) => slot,
                Err(_) => break,
            },
            _ = connection.closed() => break,
        };
        let (state, watches) = (state.clone(), budget.watches.clone());
        requests.spawn(async move {
            answer(send, recv, id, &state, Some(&watches)).await;
            drop(slot);
        });
    }
    // Closing does not cancel accepted requests; their recorded effects complete.
    while requests.join_next().await.is_some() {}
}

/// Read one request, execute it and reply. The request stays in flight until the source has
/// acknowledged the reply, so no close can discard an answer. Only `ciao/peer/2` passes the
/// source's watch slots; without them a watch is an unknown request.
async fn answer(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    id: EndpointId,
    state: &Arc<RuntimeState>,
    watches: Option<&Arc<tokio::sync::Semaphore>>,
) {
    let result = timeout(DEADLINE, async {
        let request: Request = read_request(&mut recv, Duration::from_secs(10)).await?;
        match (&request.action, watches) {
            (Action::Watch { .. }, Some(watches)) => watch(id, request, watches, state).await,
            _ => execute(id, request, state).await,
        }
    })
    .await
    .unwrap_or(Err("timeout"));
    let _ =
        agent_protocol::write_agent_frame_within(&mut send, &reply(result), peers::MAX_REPLY_BYTES)
            .await;
    let _ = send.finish();
    // Wait for the send to be acknowledged. This await is bounded and cancellation does not
    // undo an already recorded effect.
    let _ = timeout(Duration::from_secs(5), send.stopped()).await;
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
                .filter(|w| grant.scope.covers(&w.workspace_id))
                .collect();
            Ok(
                json!({"workspaces":selected, "scan_incomplete":projects.scan_incomplete, "agent":PeerAgent::Claude, "agents":[PeerAgent::Claude, PeerAgent::Codex]}),
            )
        }
        Action::Start {
            agent,
            request_id,
            workspace_id,
        } => {
            if !grant.scope.covers(&workspace_id) {
                return Err("authorization_denied");
            }
            let store = state.peers.snapshot();
            if let Some(record) = store
                .starts
                .iter()
                .find(|r| r.grant_id == grant.grant_id && r.request_id == request_id)
            {
                if record.workspace_id != workspace_id || record.agent != agent {
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
                .filter(|s| s.presence == "live" && state.peers.launched(&grant, &s.session_id))
                .count()
                + state
                    .codex_adoptions
                    .peer_sessions()
                    .iter()
                    .filter(|id| state.peers.launched(&grant, id))
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
                    agent,
                    stop_request: None,
                    grant_id: grant.grant_id.clone(),
                    request_id: request_id.clone(),
                    workspace_id: workspace_id.clone(),
                    outcome: None,
                });
                Ok(())
            })?;
            let command_id = peers::command_id(&grant.grant_id, &format!("start/{request_id}"));
            let outcome = match agent {
                PeerAgent::Claude => {
                    state
                        .managed_sessions
                        .managed_start(&workspace_id, &command_id)
                        .await
                }
                PeerAgent::Codex => {
                    let session = match state
                        .managed_sessions
                        .resolve_workspace(&workspace_id)
                        .await
                    {
                        Some((workspace, label)) if workspace.is_dir() => {
                            // Keep vendor initialization off the stack of every peer RPC.
                            Box::pin(crate::codex_adopted::start_peer(
                                state.agent_sessions.clone(),
                                state.codex_adoptions.clone(),
                                state.notifier.clone(),
                                &state.paths,
                                &workspace,
                                label,
                            ))
                            .await
                            .map(|registered| {
                                (registered.session_id, registered.process_generation)
                            })
                        }
                        _ => Err("unknown_workspace"),
                    };
                    codex_outcome(&command_id, session)
                }
            };
            state
                .peers
                .change(|s| {
                    let record = s
                        .starts
                        .iter_mut()
                        .find(|r| r.grant_id == grant.grant_id && r.request_id == request_id)
                        .ok_or("outcome_unknown")?;
                    record.outcome = Some(outcome.clone());
                    Ok(())
                })
                .map_err(|_| "outcome_unknown")?;
            Ok(json!(outcome))
        }
        Action::Snapshot { session_id } => {
            snapshot_for(state, &grant, &session_id).map(|s| json!(s))
        }
        // Served by `watch` on `ciao/peer/2` only.
        Action::Watch { .. } => Err("invalid_request"),
        Action::Command { mut command } => {
            let start = state
                .peers
                .owned_start(&grant, &command.session_id)
                .ok_or("authorization_denied")?;
            if start.stop_request.is_some() {
                return Err("session_stopped");
            }
            if (start.agent == PeerAgent::Codex
                && state
                    .codex_adoptions
                    .peer_worker(&command.session_id)
                    .is_none())
                || !start.includes_generation(command.expected_generation)
            {
                return Err("session_unavailable");
            }
            command.command_id = peers::command_id(&grant.grant_id, &command.command_id);
            // This is automation, not evidence that the person is using the phone (Spec 025).
            Ok(json!(
                state.agent_sessions.submit_peer_command(command).await
            ))
        }
        Action::StopReceipt {
            session_id,
            request_id,
        } => {
            let start = state
                .peers
                .owned_start(&grant, &session_id)
                .ok_or("authorization_denied")?;
            if let Some(worker) = state.codex_adoptions.peer_worker(&session_id) {
                if start.stop_request.as_deref() != Some(&request_id) {
                    return Err("session_unavailable");
                }
                worker.closed().await;
            }
            let generation = start.outcome.as_ref().and_then(|o| o.process_generation);
            let command_id = peers::command_id(&grant.grant_id, &format!("stop/{request_id}"));
            let result = generation
                .filter(|_| start.stop_request.as_deref() == Some(&request_id))
                .map(|generation| (session_id, generation))
                .ok_or("session_stopped");
            Ok(json!(codex_outcome(&command_id, result)))
        }
        Action::Stop {
            session_id,
            request_id,
            expected_generation,
        } => {
            let start = state
                .peers
                .owned_start(&grant, &session_id)
                .ok_or("authorization_denied")?;
            let command_id = peers::command_id(&grant.grant_id, &format!("stop/{request_id}"));
            let outcome = match start.agent {
                PeerAgent::Claude => {
                    state
                        .managed_sessions
                        .managed_stop(&session_id, expected_generation, &command_id)
                        .await
                }
                PeerAgent::Codex => {
                    let result = stop_native_codex(
                        state,
                        &start,
                        &session_id,
                        &request_id,
                        expected_generation,
                    )
                    .await;
                    codex_outcome(&command_id, result)
                }
            };
            Ok(json!(outcome))
        }
    }
}

/// The session snapshot `grant` may read: its own start, still in scope, in the generation it
/// launched. Snapshot and every watch reply come from here.
fn snapshot_for(
    state: &RuntimeState,
    grant: &Incoming,
    session_id: &str,
) -> Result<agent_protocol::AgentSessionSnapshot, &'static str> {
    let start = state
        .peers
        .owned_start(grant, session_id)
        .ok_or("authorization_denied")?;
    if start.agent == PeerAgent::Codex {
        let live = state.codex_adoptions.peer_worker(session_id).is_some();
        if start.stop_request.is_some() {
            return Err(if live {
                "session_stopping"
            } else {
                "session_stopped"
            });
        }
        if !live {
            return Err("session_unavailable");
        }
    }
    let snapshot = state
        .agent_sessions
        .snapshot(session_id)
        .or_else(|| {
            state
                .managed_sessions
                .stored_snapshot(session_id, &HashSet::new())
        })
        .filter(|snapshot| start.includes_generation(snapshot.process_generation))
        .ok_or("session_unavailable")?;
    Ok(agent_protocol::fit_snapshot_with_envelope(snapshot, |s| {
        agent_protocol::encoded_frame_len(&crate::ipc::success_response(
            &"x".repeat(crate::ipc::MAX_IPC_REQUEST_ID_BYTES),
            json!(s),
        ))
    }))
}

/// Reply once the session's snapshot no longer matches `after`, or when the wait runs out.
/// The session's change feed only wakes the wait. Each reading takes the effects gate and
/// rechecks the grant, exactly as `snapshot` does, so narrowing, revocation, stop and a
/// handback end a watch the way they end a snapshot.
async fn watch(
    id: EndpointId,
    request: Request,
    watches: &Arc<tokio::sync::Semaphore>,
    state: &Arc<RuntimeState>,
) -> Result<Value, &'static str> {
    request.validate()?;
    let Action::Watch {
        session_id,
        after,
        wait_ms,
    } = request.action
    else {
        return Err("invalid_request");
    };
    let _waiting = watches
        .clone()
        .try_acquire_owned()
        .map_err(|_| "watch_limit")?;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(u64::from(wait_ms));
    // Subscribed before the first reading, so a change between the two still wakes the wait.
    let mut changes = state
        .agent_sessions
        .subscribe_from_snapshot(&session_id)
        .map(|(_, changes)| changes);
    loop {
        let current = {
            let _effects = state.peers.effects.lock().await;
            let grant = state
                .peers
                .incoming(id, Some(&request.grant_id))
                .ok_or("authorization_denied")?;
            snapshot_for(state, &grant, &session_id)?
        };
        if SnapshotVersion::of(&current) != after || tokio::time::Instant::now() >= deadline {
            return Ok(json!(current));
        }
        match changes.as_mut() {
            Some(feed) => match tokio::time::timeout_at(deadline, feed.recv()).await {
                Err(_) | Ok(Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
                // The session left the live registry: read it once more, then wait out the rest.
                Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => changes = None,
            },
            None => tokio::time::sleep_until(deadline).await,
        }
    }
}

async fn stop_native_codex(
    state: &RuntimeState,
    start: &StartRecord,
    session: &str,
    request_id: &str,
    generation: u64,
) -> Result<(String, u64), &'static str> {
    if !start.includes_generation(generation) {
        return Err("stale_generation");
    }
    let worker = state.codex_adoptions.peer_worker(session);
    if let Some(previous) = &start.stop_request {
        if previous != request_id {
            return Err("session_stopped");
        }
        if let Some(worker) = worker {
            worker.closed().await;
        }
    } else {
        let worker = worker.ok_or("session_unavailable")?;
        state.peers.change(|store| {
            let record = store
                .starts
                .iter_mut()
                .find(|r| r.grant_id == start.grant_id && r.request_id == start.request_id)
                .ok_or("outcome_unknown")?;
            record.stop_request = Some(request_id.into());
            Ok(())
        })?;
        // Once durably requested, a stop must finish even if this peer loses its connection.
        tokio::spawn(async move {
            let _ = worker
                .send(crate::codex_adopted::ReleaseReason::PeerStop)
                .await;
            worker.closed().await;
        })
        .await
        .map_err(|_| "outcome_unknown")?;
    }
    Ok((session.into(), generation))
}

fn codex_outcome(
    command_id: &str,
    result: Result<(String, u64), &'static str>,
) -> LifecycleOutcome {
    let mut outcome = LifecycleOutcome {
        v: agent_protocol::AGENT_PROTOCOL_VERSION,
        command_id: command_id.into(),
        state: "accepted".into(),
        session_id: None,
        process_generation: None,
        reason_code: None,
        deduplicated: None,
        resume_command: None,
    };
    match result {
        Ok((session, generation)) => {
            outcome.session_id = Some(session);
            outcome.process_generation = Some(generation);
        }
        Err(reason) => {
            outcome.state = "refused".into();
            outcome.reason_code = Some(reason.into());
        }
    }
    outcome
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
    /// The session's next snapshot for `ciao peers follow`, and how it came.
    Follow {
        host: String,
        session_id: String,
        #[serde(default)]
        after: Option<SnapshotVersion>,
        wait_ms: u32,
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
        Local::Follow {
            host,
            session_id,
            after,
            wait_ms,
        } => follow(&host, &session_id, after, wait_ms, endpoint, state).await,
        Local::Stop {
            host,
            session_id,
            request_id,
        } => {
            let value = match call(
                &host,
                Action::Snapshot {
                    session_id: session_id.clone(),
                },
                endpoint,
                state,
            )
            .await
            {
                Ok(value) => value,
                Err("session_stopped" | "session_stopping") => {
                    return call(
                        &host,
                        Action::StopReceipt {
                            session_id,
                            request_id,
                        },
                        endpoint,
                        state,
                    )
                    .await;
                }
                Err(error) => return Err(error),
            };
            let snapshot: agent_protocol::AgentSessionSnapshot =
                serde_json::from_value(value).map_err(|_| "invalid_response")?;
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

/// One follow step. A `ciao/peer/2` destination waits for a change; anything else, or a
/// destination whose watches are busy or unknown, answers with a plain snapshot to poll.
async fn follow(
    host: &str,
    session_id: &str,
    after: Option<SnapshotVersion>,
    wait_ms: u32,
    endpoint: &Endpoint,
    state: &Arc<RuntimeState>,
) -> Result<Value, &'static str> {
    let snapshot = || Action::Snapshot {
        session_id: session_id.into(),
    };
    let watched = call_negotiated(host, endpoint, state, |protocol| match (protocol, after) {
        (PeerProtocol::Streams, Some(after)) => Action::Watch {
            session_id: session_id.into(),
            after,
            wait_ms,
        },
        _ => snapshot(),
    })
    .await;
    let (mode, value) = match watched {
        Ok((PeerProtocol::Streams, value)) => (FollowMode::Pushed, value),
        Ok((PeerProtocol::SingleRequest, value)) => (FollowMode::Polled, value),
        Err("watch_limit" | "peer_refused") if after.is_some() => (
            FollowMode::Polled,
            call(host, snapshot(), endpoint, state).await?,
        ),
        Err(error) => return Err(error),
    };
    let snapshot: agent_protocol::AgentSessionSnapshot =
        serde_json::from_value(value).map_err(|_| "invalid_response")?;
    // The local reply wraps the snapshot, so it must fit with the wrapper.
    let snapshot = agent_protocol::fit_snapshot_with_envelope(snapshot, |s| {
        agent_protocol::encoded_frame_len(&crate::ipc::success_response(
            &"x".repeat(crate::ipc::MAX_IPC_REQUEST_ID_BYTES),
            json!({"mode": mode, "snapshot": s}),
        ))
    });
    Ok(json!({"mode": mode, "snapshot": snapshot}))
}

async fn call(
    host: &str,
    action: Action,
    endpoint: &Endpoint,
    state: &Arc<RuntimeState>,
) -> Result<Value, &'static str> {
    call_negotiated(host, endpoint, state, |_| action.clone())
        .await
        .map(|(_, value)| value)
}

/// Send one request to a linked destination and say which protocol carried it. `action` may
/// depend on that protocol; both forms are validated before anything is sent.
async fn call_negotiated(
    host: &str,
    endpoint: &Endpoint,
    state: &Arc<RuntimeState>,
    action: impl Fn(PeerProtocol) -> Action,
) -> Result<(PeerProtocol, Value), &'static str> {
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
    let request = |protocol| Request {
        v: 1,
        grant_id: link.grant_id.clone(),
        action: action(protocol),
    };
    for protocol in PeerProtocol::ACCEPTED {
        request(protocol).validate()?;
    }
    let streams =
        |result: Result<Value, &'static str>| result.map(|value| (PeerProtocol::Streams, value));
    // Requests on a kept connection run side by side and never wait for the lane.
    if let Some(kept) = state.peers.outbound.reuse(id)
        && let Sent::Answered(result) = ask(&kept.connection, &request(PeerProtocol::Streams)).await
    {
        return streams(result);
    }
    // Nothing was sent: the kept connection had closed or expired, or no stream opened.
    let lane = state.peers.outbound_lane(id);
    let turn = lane.lock().await;
    if !state.peers.snapshot().outgoing.contains(link) {
        return Err("unknown_or_ambiguous_peer");
    }
    // Dialing is single-flight: another request may have connected while this one waited.
    let kept = match state.peers.outbound.reuse(id) {
        Some(kept) => kept,
        None => {
            let connection = timeout(Duration::from_secs(10), dial(endpoint, id))
                .await
                .map_err(|_| "peer_unreachable")?
                .map_err(connect_error)?;
            match PeerProtocol::negotiated(connection.alpn()) {
                Some(PeerProtocol::Streams) => state.peers.outbound.adopt(id, connection),
                // A destination that closes after one request. Hold the lane until it has.
                Some(PeerProtocol::SingleRequest) => {
                    return exchange(&connection, &request(PeerProtocol::SingleRequest))
                        .await
                        .map(|value| (PeerProtocol::SingleRequest, value));
                }
                None => {
                    connection.close(VarInt::from_u32(0), b"peer protocol unsupported");
                    return Err("unsupported_version");
                }
            }
        }
    };
    drop(turn);
    match ask(&kept.connection, &request(PeerProtocol::Streams)).await {
        Sent::Answered(result) => streams(result),
        Sent::NotSent => Err("connection_lost"),
    }
}

/// Offer both protocols in one handshake; the destination picks.
async fn dial(
    endpoint: &Endpoint,
    id: EndpointId,
) -> Result<Connection, iroh::endpoint::ConnectError> {
    let connecting = endpoint
        .connect_with_opts(
            id,
            PeerProtocol::Streams.alpn(),
            iroh::endpoint::ConnectOptions::new()
                .with_additional_alpns(vec![PeerProtocol::SingleRequest.alpn().to_vec()]),
        )
        .await?;
    Ok(connecting.await?)
}

/// Whether a request left this host. Only a request that never did may be sent again.
enum Sent {
    NotSent,
    Answered(Result<Value, &'static str>),
}

/// One request on its own stream of a kept connection.
async fn ask(connection: &Connection, request: &Request) -> Sent {
    let Ok((send, recv)) = connection.open_bi().await else {
        return Sent::NotSent;
    };
    Sent::Answered(
        match timeout(DEADLINE, send_request(send, recv, request)).await {
            Ok(Ok(reply)) => outcome(reply, request),
            // No reply arrived. A closed connection names the cause; once the request was written,
            // an effect may or may not have happened.
            Ok(Err(code)) => Err(match connection.close_reason() {
                None => code,
                reason => close_error(reason).unwrap_or(if request.action.has_effect() {
                    "outcome_unknown"
                } else {
                    "connection_lost"
                }),
            }),
            Err(_) => Err("outcome_unknown"),
        },
    )
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

/// The `ciao/peer/1` exchange: one request, then the destination's close.
async fn exchange(connection: &Connection, request: &Request) -> Result<Value, &'static str> {
    let result = timeout(DEADLINE, async {
        let (send, recv) = connection.open_bi().await.map_err(|_| "connection_lost")?;
        let response = send_request(send, recv, request).await?;
        // The destination closes after it releases this endpoint's admission slot. Returning
        // on just the reply allowed the next snapshot/send to race that release.
        let _ = timeout(Duration::from_secs(5), connection.closed()).await;
        outcome(response, request)
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

/// Write one request on a fresh stream and read its reply.
async fn send_request(
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    request: &Request,
) -> Result<Reply, &'static str> {
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
    Ok(response)
}

fn outcome(response: Reply, request: &Request) -> Result<Value, &'static str> {
    match (response.result, response.error) {
        (None, Some(code))
            if code == "invalid_request"
                && matches!(
                    request.action,
                    Action::Start {
                        agent: PeerAgent::Codex,
                        ..
                    }
                ) =>
        {
            Err("unsupported_peer_agent")
        }
        (Some(result), None) => Ok(result),
        (None, Some(code)) => Err(remote_error(&code)),
        _ => Err("invalid_response"),
    }
}

fn remote_error(code: &str) -> &'static str {
    match code {
        "authorization_denied" => "authorization_denied",
        "worker_limit" => "worker_limit",
        "request_limit" => "request_limit",
        "outcome_unknown" => "outcome_unknown",
        "request_id_reused" => "request_id_reused",
        "session_unavailable" => "session_unavailable",
        "session_stopped" => "session_stopped",
        "session_stopping" => "session_stopping",
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
                .alpns(super::super::endpoint_alpns())
                .transport_config(host_transport_config());
            if let Some(map) = crate::relay::configured_map().unwrap() {
                builder = builder.relay_mode(RelayMode::Custom(map));
            }
            let endpoint = builder.bind().await.unwrap();
            let listener = super::super::bind_local_socket(&paths.socket_file)
                .await
                .unwrap();
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

    async fn timed(
        body: Value,
        client: &Endpoint,
        source: &Arc<RuntimeState>,
    ) -> (f64, Result<Value, &'static str>) {
        let began = std::time::Instant::now();
        let result = ipc(body, client, source).await;
        (began.elapsed().as_secs_f64() * 1000.0, result)
    }

    /// Peer latency lab (2026-11-23). It drives the source daemon's real IPC entry point against
    /// a real destination over real Iroh on loopback, with the fake launcher. Run it inside a
    /// network namespace whose loopback adds a fixed delay to count network round trips.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "latency lab; requires CIAO_PEER_LATENCY_LAB, an output JSON path"]
    async fn peer_latency_lab() {
        let out = PathBuf::from(std::env::var("CIAO_PEER_LATENCY_LAB").expect("output path"));
        let samples: usize = std::env::var("CIAO_PEER_LATENCY_SAMPLES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(10);
        let follow_for = Duration::from_secs(
            std::env::var("CIAO_PEER_LATENCY_FOLLOW_SECONDS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(20),
        );
        // "1" stands in for a 0.1.66 destination, which only accepts ciao/peer/1.
        let alpns = match std::env::var("CIAO_PEER_LATENCY_PROTOCOLS").as_deref() {
            Ok("1") => vec![peers::ALPN.to_vec()],
            _ => accepted_alpns(),
        };
        let pair = pair(alpns).await;
        let Pair {
            destination,
            source,
            host,
            client,
            ids,
            grant,
            ..
        } = &pair;
        let mut report = serde_json::Map::new();
        let mut series = |name: &str, values: Vec<f64>| {
            report.insert(name.into(), json!(values));
        };
        // Before any kept connection: the single-request exchange, step by step: handshake, request to reply, reply to close.
        let request = req(grant, Action::Workspaces {});
        let mut phases = [Vec::new(), Vec::new(), Vec::new()];
        for _ in 0..samples {
            let began = std::time::Instant::now();
            let connection = client.connect(host.id(), peers::ALPN).await.unwrap();
            let connected = std::time::Instant::now();
            let (mut send, mut recv) = connection.open_bi().await.unwrap();
            agent_protocol::write_agent_frame(&mut send, &request)
                .await
                .unwrap();
            send.finish().unwrap();
            let reply: Reply = read_request(&mut recv, DEADLINE).await.unwrap();
            assert!(reply.error.is_none());
            let answered = std::time::Instant::now();
            let _ = timeout(Duration::from_secs(5), connection.closed()).await;
            let closed = std::time::Instant::now();
            for (phase, (from, to)) in phases.iter_mut().zip([
                (began, connected),
                (connected, answered),
                (answered, closed),
            ]) {
                phase.push(to.duration_since(from).as_secs_f64() * 1000.0);
            }
        }
        let [handshake, exchange, close] = phases;
        series("v1_handshake", handshake);
        series("v1_request_reply", exchange);
        series("v1_reply_to_close", close);
        let workspaces = json!({"op":"call","host":"Build","action":{"op":"workspaces"}});
        let (first, result) = timed(workspaces.clone(), client, source).await;
        result.unwrap();
        series("first_workspaces", vec![first]);
        let kept = source.peers.outbound.kept(host.id()).is_some();
        let protocol = if kept { "ciao/peer/2" } else { "ciao/peer/1" };
        let mut values = Vec::new();
        for _ in 0..samples {
            let (ms, result) = timed(workspaces.clone(), client, source).await;
            result.unwrap();
            values.push(ms);
        }
        series("workspaces", values);
        let (ms, result) = timed(
            json!({"op":"call","host":"Build","action":{"op":"start","request_id":"lab-start","workspace_id":ids[0]}}),
            client,
            source,
        )
        .await;
        let started = result.unwrap();
        series("start", vec![ms]);
        let session = started["session_id"].as_str().unwrap().to_owned();
        let mut bridge = register(destination, &session).await;
        let drain = tokio::spawn(async move { while bridge.recv().await.is_some() {} });
        let snapshot =
            json!({"op":"call","host":"Build","action":{"op":"snapshot","session_id":session}});
        let mut values = Vec::new();
        for _ in 0..samples {
            let (ms, result) = timed(snapshot.clone(), client, source).await;
            assert_eq!(result.unwrap()["presence"], "live");
            values.push(ms);
        }
        series("snapshot", values);
        for (name, text) in [("send", json!("lab prompt")), ("interrupt", Value::Null)] {
            let mut values = Vec::new();
            for i in 0..samples {
                let (ms, result) = timed(
                    json!({"op":"send","host":"Build","session_id":session,"request_id":format!("lab-{name}-{i}"),"text":text}),
                    client,
                    source,
                )
                .await;
                let receipt = result.unwrap();
                assert!(receipt["state"] != "rejected", "{receipt}");
                values.push(ms);
            }
            series(name, values);
        }
        // Follow lag: the destination changes the session at irregular times while the source
        // follows it. Lag is the change until the source holds a snapshot that includes it.
        let changes = Arc::new(Mutex::new(Vec::<(std::time::Instant, u64)>::new()));
        let mutator = tokio::spawn({
            let destination = destination.clone();
            let session = session.clone();
            let changes = changes.clone();
            async move {
                let mut i = 0_u64;
                loop {
                    tokio::time::sleep(Duration::from_millis(700 + (i * 389) % 1100)).await;
                    let mode = if i.is_multiple_of(2) {
                        "plan"
                    } else {
                        "default"
                    };
                    destination
                        .agent_sessions
                        .update_bridge_permission_mode(&session, mode.into());
                    let revision = destination
                        .agent_sessions
                        .snapshot(&session)
                        .unwrap()
                        .revision;
                    changes.lock().push((std::time::Instant::now(), revision));
                    i += 1;
                }
            }
        });
        let seen = follow_for_lab(client, source, &session, follow_for).await;
        mutator.abort();
        let changes = changes.lock().clone();
        let lags: Vec<f64> = changes
            .iter()
            .filter_map(|(at, revision)| {
                seen.iter()
                    .find(|(_, seen)| seen >= revision)
                    .map(|(when, _)| when.duration_since(*at).as_secs_f64() * 1000.0)
            })
            .collect();
        report.insert("protocol".into(), json!(protocol));
        report.insert("follow_snapshots".into(), json!(seen.len()));
        report.insert("follow_changes".into(), json!(changes.len()));
        report.insert("follow_lag".into(), json!(lags));
        let (ms, result) = timed(
            json!({"op":"stop","host":"Build","session_id":session,"request_id":"lab-stop"}),
            client,
            source,
        )
        .await;
        let stopped = result.unwrap();
        assert!(stopped["state"] != "rejected", "{stopped}");
        report.insert("stop".into(), json!([ms]));
        drain.abort();
        report.insert("connections_accepted".into(), json!(pair.accepted()));
        crate::storage::atomic_write_private(&out, &serde_json::to_vec_pretty(&report).unwrap())
            .unwrap();
        pair.close().await;
    }

    /// The CLI's follow loop with the lab's clock. Returns when each snapshot arrived and its
    /// revision.
    async fn follow_for_lab(
        client: &Endpoint,
        source: &Arc<RuntimeState>,
        session: &str,
        seconds: Duration,
    ) -> Vec<(std::time::Instant, u64)> {
        let mut seen = Vec::new();
        crate::peer_cli::follow(
            &LabFollow {
                client,
                source,
                session,
            },
            seconds,
            |snapshot| {
                seen.push((
                    std::time::Instant::now(),
                    snapshot["revision"].as_u64().unwrap(),
                ));
                Ok(())
            },
        )
        .await
        .unwrap();
        seen
    }

    impl Pair {
        fn spawn_local(&self, body: Value) -> tokio::task::JoinHandle<Result<Value, &'static str>> {
            let (client, source) = (self.client.clone(), self.source.clone());
            tokio::spawn(async move { ipc(body, &client, &source).await })
        }

        fn budget(&self) -> SourceBudget {
            self.destination.peers.connections.lock()[&self.client.id().to_string()]
                .budget
                .clone()
        }
    }

    fn follow_body(session: &str, after: Option<SnapshotVersion>, wait_ms: u32) -> Value {
        json!({"op":"follow","host":"Build","session_id":session,"after":after,"wait_ms":wait_ms})
    }

    #[tokio::test]
    async fn peer_follow_waits_for_a_change_and_replies_within_its_wait() {
        let pair = pair(accepted_alpns()).await;
        let (session, drain) = pair.start_live("one").await;
        let first = pair.local(follow_body(&session, None, 1000)).await.unwrap();
        assert_eq!(first["mode"], "pushed");
        let held = SnapshotVersion::of_value(&first["snapshot"]).unwrap();
        // Unchanged: the reply comes when the wait runs out, with the same version.
        let began = std::time::Instant::now();
        let same = pair
            .local(follow_body(&session, Some(held), 300))
            .await
            .unwrap();
        assert!(began.elapsed() >= Duration::from_millis(300));
        assert_eq!(SnapshotVersion::of_value(&same["snapshot"]), Some(held));
        // A change ends the wait at once.
        let waiting = pair.spawn_local(follow_body(&session, Some(held), 10_000));
        let budget = pair.budget();
        until(|| budget.watches.available_permits() == peers::MAX_SOURCE_WATCHES - 1).await;
        let changed = std::time::Instant::now();
        pair.destination
            .agent_sessions
            .update_bridge_permission_mode(&session, "plan".into());
        let reply = waiting.await.unwrap().unwrap();
        assert!(changed.elapsed() < Duration::from_secs(5));
        let seen = SnapshotVersion::of_value(&reply["snapshot"]).unwrap();
        assert!(seen.revision > held.revision);
        // A version the source holds is already stale: the reply is immediate.
        let began = std::time::Instant::now();
        let stale = pair
            .local(follow_body(&session, Some(held), 10_000))
            .await
            .unwrap();
        assert!(began.elapsed() < Duration::from_secs(5));
        assert_eq!(SnapshotVersion::of_value(&stale["snapshot"]), Some(seen));
        assert_eq!(pair.accepted(), 1);
        drain.abort();
        pair.close().await;
    }

    #[tokio::test]
    async fn peer_follow_rechecks_the_grant_for_every_reply() {
        let pair = pair(accepted_alpns()).await;
        let (session, drain) = pair.start_live("one").await;
        let first = pair.local(follow_body(&session, None, 1000)).await.unwrap();
        let held = SnapshotVersion::of_value(&first["snapshot"]).unwrap();
        let waiting = pair.spawn_local(follow_body(&session, Some(held), 10_000));
        let budget = pair.budget();
        until(|| budget.watches.available_permits() == peers::MAX_SOURCE_WATCHES - 1).await;
        // Narrowing keeps the connection open, so the waiting reply must be refused itself.
        admin(
            update(
                pair.client.id(),
                GrantScope::Selected(vec![pair.ids[1].clone()]),
            ),
            None,
            &pair.destination,
        )
        .await
        .unwrap();
        pair.destination
            .agent_sessions
            .update_bridge_permission_mode(&session, "plan".into());
        assert_eq!(waiting.await.unwrap().unwrap_err(), "authorization_denied");
        assert_eq!(
            pair.local(follow_body(&session, Some(held), 1000))
                .await
                .unwrap_err(),
            "authorization_denied"
        );
        drain.abort();
        pair.close().await;
    }

    #[tokio::test]
    async fn peer_follow_ends_when_a_codex_session_is_handed_back() {
        let pair = pair(accepted_alpns()).await;
        install_codex_fixture(&pair.destination.paths);
        let started = pair
            .call(json!({"op":"start","agent":"codex","request_id":"codex","workspace_id":pair.ids[0]}))
            .await
            .unwrap();
        let session = started["session_id"].as_str().unwrap().to_owned();
        let first = pair.local(follow_body(&session, None, 1000)).await.unwrap();
        let held = SnapshotVersion::of_value(&first["snapshot"]).unwrap();
        let waiting = pair.spawn_local(follow_body(&session, Some(held), 10_000));
        let budget = pair.budget();
        until(|| budget.watches.available_permits() == peers::MAX_SOURCE_WATCHES - 1).await;
        let began = std::time::Instant::now();
        let worker = pair
            .destination
            .codex_adoptions
            .peer_worker(&session)
            .unwrap();
        worker
            .send(crate::codex_adopted::ReleaseReason::ResumeInTerminal)
            .await
            .unwrap();
        worker.closed().await;
        let _human = register(&pair.destination, &session).await;
        assert_eq!(waiting.await.unwrap().unwrap_err(), "session_unavailable");
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "the handback woke the wait"
        );
        pair.close().await;
    }

    #[tokio::test]
    async fn peer_follow_polls_when_watches_are_busy_or_the_destination_is_single_request() {
        let pair = pair(accepted_alpns()).await;
        let (session, drain) = pair.start_live("one").await;
        let first = pair.local(follow_body(&session, None, 1000)).await.unwrap();
        let held = SnapshotVersion::of_value(&first["snapshot"]).unwrap();
        let waiting: Vec<_> = (0..peers::MAX_SOURCE_WATCHES)
            .map(|_| pair.spawn_local(follow_body(&session, Some(held), 10_000)))
            .collect();
        let budget = pair.budget();
        until(|| budget.watches.available_permits() == 0).await;
        let began = std::time::Instant::now();
        let polled = pair
            .local(follow_body(&session, Some(held), 10_000))
            .await
            .unwrap();
        assert_eq!(polled["mode"], "polled");
        assert!(began.elapsed() < Duration::from_secs(5));
        pair.destination
            .agent_sessions
            .update_bridge_permission_mode(&session, "plan".into());
        for waiting in waiting {
            assert_eq!(waiting.await.unwrap().unwrap()["mode"], "pushed");
        }
        drain.abort();
        pair.close().await;

        let pair = self::pair(vec![peers::ALPN.to_vec()]).await;
        let (session, drain) = pair.start_live("one").await;
        let first = pair.local(follow_body(&session, None, 1000)).await.unwrap();
        assert_eq!(first["mode"], "polled");
        let held = SnapshotVersion::of_value(&first["snapshot"]).unwrap();
        let began = std::time::Instant::now();
        let polled = pair
            .local(follow_body(&session, Some(held), 10_000))
            .await
            .unwrap();
        assert_eq!(polled["mode"], "polled");
        assert!(began.elapsed() < Duration::from_secs(5));
        drain.abort();
        pair.close().await;
    }

    #[tokio::test]
    async fn peer_cli_follow_reads_changes_through_the_local_daemon_socket() {
        let pair = pair(accepted_alpns()).await;
        let (session, drain) = pair.start_live("one").await;
        let run_dir = tempfile::tempdir().unwrap();
        let socket = run_dir.path().join("ciao.sock");
        let listener = super::super::bind_local_socket(&socket).await.unwrap();
        let server = tokio::spawn(super::super::serve_ipc(
            listener,
            pair.client.clone(),
            pair.source.clone(),
        ));
        let began = std::time::Instant::now();
        let change = tokio::spawn({
            let (destination, session) = (pair.destination.clone(), session.clone());
            async move {
                tokio::time::sleep(Duration::from_millis(1100)).await;
                destination
                    .agent_sessions
                    .update_bridge_permission_mode(&session, "plan".into());
            }
        });
        let source = crate::peer_cli::DaemonFollow::new(&socket, "Build".into(), session.clone());
        let mut lines = Vec::new();
        crate::peer_cli::follow(&source, Duration::from_secs(3), |snapshot| {
            lines.push((began.elapsed(), snapshot["revision"].as_u64().unwrap()));
            Ok(())
        })
        .await
        .unwrap();
        change.await.unwrap();
        assert!(lines.len() >= 4, "{lines:?}");
        assert!(lines[0].0 < Duration::from_secs(1));
        assert!(
            lines
                .windows(2)
                .all(|w| w[1].0 - w[0].0 < Duration::from_millis(1500)),
            "{lines:?}"
        );
        // Polling once a second would see the 1.1 s change at about 2 s.
        let seen = lines.iter().find(|l| l.1 > lines[0].1).unwrap();
        assert!(seen.0 < Duration::from_millis(1800), "{lines:?}");
        server.abort();
        drain.abort();
        pair.close().await;
    }

    /// The CLI's follow loop, reading through the source daemon's IPC handler in process.
    struct LabFollow<'a> {
        client: &'a Endpoint,
        source: &'a Arc<RuntimeState>,
        session: &'a str,
    }

    impl crate::peer_cli::FollowSource for LabFollow<'_> {
        async fn changed(
            &self,
            after: Option<SnapshotVersion>,
            wait: Duration,
        ) -> anyhow::Result<Option<crate::peer_cli::FollowStep>> {
            let wait_ms = u32::try_from(wait.as_millis()).unwrap();
            let value = ipc(
                follow_body(self.session, after, wait_ms),
                self.client,
                self.source,
            )
            .await
            .map_err(anyhow::Error::msg)?;
            Ok(Some(serde_json::from_value(value)?))
        }

        async fn snapshot(&self) -> anyhow::Result<Value> {
            ipc(
                json!({"op":"call","host":"Build","action":{"op":"snapshot","session_id":self.session}}),
                self.client,
                self.source,
            )
            .await
            .map_err(anyhow::Error::msg)
        }
    }

    fn accepted_alpns() -> Vec<Vec<u8>> {
        PeerProtocol::ACCEPTED.map(|p| p.alpn().to_vec()).to_vec()
    }

    async fn endpoint(
        alpns: Vec<Vec<u8>>,
        key: iroh::SecretKey,
        lookup: &iroh::address_lookup::memory::MemoryLookup,
    ) -> Endpoint {
        Endpoint::builder(presets::N0DisableRelay)
            .secret_key(key)
            .alpns(alpns)
            .address_lookup(lookup.clone())
            .transport_config(super::super::host_transport_config())
            .bind()
            .await
            .unwrap()
    }

    /// Serve `host` through the daemon's dispatcher, counting the connections it accepts.
    fn serve_counting(
        host: &Endpoint,
        state: &Arc<RuntimeState>,
    ) -> Arc<std::sync::atomic::AtomicUsize> {
        let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        tokio::spawn({
            let (host, state, accepted) = (host.clone(), state.clone(), accepted.clone());
            async move {
                while let Some(incoming) = host.accept().await {
                    let Ok(connection) = incoming.await else {
                        continue;
                    };
                    accepted.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(super::super::handle_authenticated_connection(
                        connection,
                        state.clone(),
                    ));
                }
            }
        });
        accepted
    }

    /// A source and a destination on real Iroh over loopback, linked as "Build".
    struct Pair {
        _homes: (TempDir, TempDir),
        destination: Arc<RuntimeState>,
        source: Arc<RuntimeState>,
        host: Endpoint,
        client: Endpoint,
        client_key: iroh::SecretKey,
        lookup: iroh::address_lookup::memory::MemoryLookup,
        ids: Vec<String>,
        grant: String,
        accepted: Arc<std::sync::atomic::AtomicUsize>,
    }

    async fn pair(alpns: Vec<Vec<u8>>) -> Pair {
        let (home, mut destination, _, ids, grant) = fixture().await;
        let lookup = iroh::address_lookup::memory::MemoryLookup::new();
        let host = endpoint(alpns, iroh::SecretKey::generate(), &lookup).await;
        let client_key = iroh::SecretKey::generate();
        let client = endpoint(Vec::new(), client_key.clone(), &lookup).await;
        lookup.add_endpoint_info(host.addr());
        Arc::get_mut(&mut destination).unwrap().host_endpoint_id = host.id();
        destination
            .peers
            .change(|s| {
                s.incoming[0].peer.endpoint_id = client.id().to_string();
                Ok(())
            })
            .unwrap();
        let source_home = tempfile::tempdir().unwrap();
        let source =
            super::super::tests::test_state(client.id(), &source_home.path().join("paired.json"));
        source
            .peers
            .change(|s| {
                s.outgoing.push(Outgoing {
                    peer: Descriptor {
                        endpoint_id: host.id().to_string(),
                        name: "Build".into(),
                    },
                    grant_id: grant.clone(),
                });
                Ok(())
            })
            .unwrap();
        let accepted = serve_counting(&host, &destination);
        Pair {
            _homes: (home, source_home),
            destination,
            source,
            host,
            client,
            client_key,
            lookup,
            ids,
            grant,
            accepted,
        }
    }

    impl Pair {
        async fn call(&self, action: Value) -> Result<Value, &'static str> {
            self.local(json!({"op":"call","host":"Build","action":action}))
                .await
        }

        async fn local(&self, body: Value) -> Result<Value, &'static str> {
            ipc(body, &self.client, &self.source).await
        }

        fn spawn_call(
            &self,
            action: Value,
        ) -> tokio::task::JoinHandle<Result<Value, &'static str>> {
            let (client, source) = (self.client.clone(), self.source.clone());
            tokio::spawn(async move {
                ipc(
                    json!({"op":"call","host":"Build","action":action}),
                    &client,
                    &source,
                )
                .await
            })
        }

        fn accepted(&self) -> usize {
            self.accepted.load(Ordering::SeqCst)
        }

        async fn start_live(&self, request_id: &str) -> (String, tokio::task::JoinHandle<()>) {
            let started = self
                .call(json!({"op":"start","request_id":request_id,"workspace_id":self.ids[0]}))
                .await
                .unwrap();
            let session = started["session_id"].as_str().unwrap().to_owned();
            let mut bridge = register(&self.destination, &session).await;
            let drain = tokio::spawn(async move { while bridge.recv().await.is_some() {} });
            (session, drain)
        }

        async fn close(self) {
            self.client.close().await;
            self.host.close().await;
        }
    }

    async fn until(condition: impl Fn() -> bool) {
        timeout(Duration::from_secs(5), async {
            while !condition() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("condition within five seconds");
    }

    #[tokio::test]
    async fn peer_streams_carry_every_operation_on_one_kept_connection() {
        let pair = pair(accepted_alpns()).await;
        let listed = pair.call(json!({"op":"workspaces"})).await.unwrap();
        assert_eq!(listed["workspaces"].as_array().unwrap().len(), 2);
        let kept = pair.source.peers.outbound.kept(pair.host.id()).unwrap();
        assert_eq!(kept.alpn(), peers::ALPN_STREAMS);
        let (session, drain) = pair.start_live("one").await;
        let snapshot = json!({"op":"snapshot","session_id":session});
        assert_eq!(
            pair.call(snapshot.clone()).await.unwrap()["presence"],
            "live"
        );
        for (id, text) in [("prompt", json!("hello")), ("interrupt", Value::Null)] {
            let receipt = pair
                .local(json!({"op":"send","host":"Build","session_id":session,"request_id":id,"text":text}))
                .await
                .unwrap();
            assert_ne!(receipt["state"], "rejected", "{receipt}");
        }
        // Requests on a kept connection do not take turns. With the destination's effects gate
        // held, three run on it at once instead of queueing behind the source's lane.
        let budget = pair.destination.peers.connections.lock()[&pair.client.id().to_string()]
            .budget
            .clone();
        let gate = pair.destination.peers.effects.lock().await;
        let calls: Vec<_> = (0..3).map(|_| pair.spawn_call(snapshot.clone())).collect();
        until(|| budget.requests.available_permits() == peers::MAX_SOURCE_REQUESTS - 3).await;
        drop(gate);
        for call in calls {
            assert_eq!(call.await.unwrap().unwrap()["presence"], "live");
        }
        let stopped = pair
            .local(json!({"op":"stop","host":"Build","session_id":session,"request_id":"stop"}))
            .await
            .unwrap();
        assert_ne!(stopped["state"], "rejected", "{stopped}");
        assert_eq!(pair.accepted(), 1, "one connection carried every request");
        let still = pair.source.peers.outbound.kept(pair.host.id()).unwrap();
        assert_eq!(still.stable_id(), kept.stable_id());
        drain.abort();
        pair.close().await;
    }

    #[tokio::test]
    async fn peer_new_source_takes_turns_with_a_single_request_destination() {
        // A destination that only speaks ciao/peer/1 stands in for 0.1.66.
        let pair = pair(vec![peers::ALPN.to_vec()]).await;
        pair.call(json!({"op":"workspaces"})).await.unwrap();
        assert!(pair.source.peers.outbound.kept(pair.host.id()).is_none());
        let (session, drain) = pair.start_live("one").await;
        let snapshot = json!({"op":"snapshot","session_id":session});
        pair.call(snapshot.clone()).await.unwrap();
        let receipt = pair
            .local(json!({"op":"send","host":"Build","session_id":session,"request_id":"prompt","text":"hello"}))
            .await
            .unwrap();
        assert_ne!(receipt["state"], "rejected", "{receipt}");
        assert_eq!(
            pair.accepted(),
            5,
            "one connection per request, send making two"
        );
        // Concurrent calls still take turns: one holds the lane while it is admitted, and none
        // is refused as busy.
        let gate = pair.destination.peers.effects.lock().await;
        let calls: Vec<_> = (0..3).map(|_| pair.spawn_call(snapshot.clone())).collect();
        until(|| pair.accepted() == 6).await;
        assert!(
            pair.source
                .peers
                .outbound_lane(pair.host.id())
                .try_lock()
                .is_err()
        );
        drop(gate);
        for call in calls {
            assert_eq!(call.await.unwrap().unwrap()["presence"], "live");
        }
        assert_eq!(pair.accepted(), 8);
        assert!(pair.source.peers.outbound.kept(pair.host.id()).is_none());
        drain.abort();
        pair.close().await;
    }

    #[tokio::test]
    async fn peer_single_request_source_still_gets_one_request_per_connection() {
        let pair = pair(accepted_alpns()).await;
        // A 0.1.66 source offers only ciao/peer/1 and waits for the destination to close.
        for _ in 0..3 {
            let connection = pair
                .client
                .connect(pair.host.id(), peers::ALPN)
                .await
                .unwrap();
            assert_eq!(connection.alpn(), peers::ALPN);
            let began = std::time::Instant::now();
            let listed = exchange(&connection, &req(&pair.grant, Action::Workspaces {}))
                .await
                .unwrap();
            assert_eq!(listed["workspaces"].as_array().unwrap().len(), 2);
            assert!(connection.close_reason().is_some());
            assert!(
                began.elapsed() < Duration::from_secs(4),
                "the destination closed after one request instead of making the source time out"
            );
        }
        assert_eq!(pair.accepted(), 3);
        pair.close().await;
    }

    #[tokio::test]
    async fn peer_source_dials_again_only_when_no_request_byte_left() {
        let pair = pair(accepted_alpns()).await;
        pair.call(json!({"op":"workspaces"})).await.unwrap();
        let kept = pair.source.peers.outbound.kept(pair.host.id()).unwrap();
        // The destination drops the connection between requests. Nothing was sent on it, so
        // the next request dials again and runs once.
        pair.destination.peers.close(&pair.client.id().to_string());
        timeout(Duration::from_secs(3), kept.closed())
            .await
            .unwrap();
        let started = pair
            .call(json!({"op":"start","request_id":"after","workspace_id":pair.ids[0]}))
            .await
            .unwrap();
        assert_eq!(started["state"], "accepted", "{started}");
        assert_eq!(pair.accepted(), 2);
        let claims = pair.destination.peers.snapshot().starts;
        assert_eq!(claims.iter().filter(|r| r.request_id == "after").count(), 1);

        // A destination that reads each request and then drops the connection unanswered.
        let host = endpoint(
            vec![peers::ALPN_STREAMS.to_vec()],
            iroh::SecretKey::generate(),
            &pair.lookup,
        )
        .await;
        pair.lookup.add_endpoint_info(host.addr());
        let (connections, requests) = (
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        );
        tokio::spawn({
            let (host, connections, requests) =
                (host.clone(), connections.clone(), requests.clone());
            async move {
                while let Some(incoming) = host.accept().await {
                    let connection = incoming.await.unwrap();
                    connections.fetch_add(1, Ordering::SeqCst);
                    let (_send, mut recv) = connection.accept_bi().await.unwrap();
                    let _: Request = read_request(&mut recv, Duration::from_secs(5))
                        .await
                        .unwrap();
                    requests.fetch_add(1, Ordering::SeqCst);
                    connection.close(VarInt::from_u32(0), b"gone");
                }
            }
        });
        pair.source
            .peers
            .change(|s| {
                s.outgoing.push(Outgoing {
                    peer: Descriptor {
                        endpoint_id: host.id().to_string(),
                        name: "Dropper".into(),
                    },
                    grant_id: "dropper-grant".into(),
                });
                Ok(())
            })
            .unwrap();
        let dropper =
            |action: Value| pair.local(json!({"op":"call","host":"Dropper","action":action}));
        assert_eq!(
            dropper(json!({"op":"start","request_id":"lost","workspace_id":"w"}))
                .await
                .unwrap_err(),
            "outcome_unknown"
        );
        assert_eq!(
            dropper(json!({"op":"snapshot","session_id":"s"}))
                .await
                .unwrap_err(),
            "connection_lost"
        );
        // Each written request reached the destination once; neither was sent again.
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        assert_eq!(connections.load(Ordering::SeqCst), 2);
        host.close().await;
        pair.close().await;
    }

    #[tokio::test]
    async fn peer_streams_supersede_the_same_source_and_single_requests_stay_busy() {
        let pair = pair(accepted_alpns()).await;
        pair.call(json!({"op":"workspaces"})).await.unwrap();
        let first = pair.source.peers.outbound.kept(pair.host.id()).unwrap();
        let key = pair.client.id().to_string();
        let budget = pair.destination.peers.connections.lock()[&key]
            .budget
            .requests
            .clone();
        // The same source key on a fresh endpoint, as after the source daemon restarts while
        // the destination still holds its old connection.
        let restarted = endpoint(Vec::new(), pair.client_key.clone(), &pair.lookup).await;
        let second = restarted
            .connect(pair.host.id(), peers::ALPN_STREAMS)
            .await
            .unwrap();
        let superseded = timeout(Duration::from_secs(3), first.closed())
            .await
            .unwrap();
        assert!(
            matches!(superseded, ConnectionError::ApplicationClosed(close)
            if close.error_code == VarInt::from_u32(CONNECTION_SUPERSEDED))
        );
        match ask(&second, &req(&pair.grant, Action::Workspaces {})).await {
            Sent::Answered(Ok(listed)) => {
                assert_eq!(listed["workspaces"].as_array().unwrap().len(), 2)
            }
            _ => panic!("the superseding connection serves requests"),
        }
        let held = pair.destination.peers.connections.lock()[&key]
            .budget
            .requests
            .clone();
        assert!(
            Arc::ptr_eq(&held, &budget),
            "a reconnect inherits the budget"
        );
        // ciao/peer/1 keeps 0.1.66 admission: busy while the endpoint holds a connection.
        let legacy = restarted
            .connect(pair.host.id(), peers::ALPN)
            .await
            .unwrap();
        assert_eq!(
            exchange(&legacy, &req(&pair.grant, Action::Workspaces {}))
                .await
                .unwrap_err(),
            "peer_busy"
        );
        restarted.close().await;
        pair.close().await;
    }

    #[tokio::test]
    async fn peer_two_way_pair_keeps_admitted_and_kept_connections_apart() {
        let (home_a, mut a, _, _, grant_a) = fixture().await;
        let (home_b, mut b, _, _, grant_b) = fixture().await;
        let lookup = iroh::address_lookup::memory::MemoryLookup::new();
        let ea = endpoint(accepted_alpns(), iroh::SecretKey::generate(), &lookup).await;
        let eb = endpoint(accepted_alpns(), iroh::SecretKey::generate(), &lookup).await;
        lookup.add_endpoint_info(ea.addr());
        lookup.add_endpoint_info(eb.addr());
        for (state, me, other, name, grant) in [
            (&mut a, &ea, &eb, "B", &grant_b),
            (&mut b, &eb, &ea, "A", &grant_a),
        ] {
            Arc::get_mut(state).unwrap().host_endpoint_id = me.id();
            state
                .peers
                .change(|s| {
                    s.incoming[0].peer.endpoint_id = other.id().to_string();
                    s.outgoing.push(Outgoing {
                        peer: Descriptor {
                            endpoint_id: other.id().to_string(),
                            name: name.into(),
                        },
                        grant_id: grant.clone(),
                    });
                    Ok(())
                })
                .unwrap();
        }
        serve_counting(&ea, &a);
        serve_counting(&eb, &b);
        let call = |from: &Arc<RuntimeState>, endpoint: &Endpoint, host: &str| {
            let (from, endpoint, host) = (from.clone(), endpoint.clone(), host.to_owned());
            async move {
                ipc(
                    json!({"op":"call","host":host,"action":{"op":"workspaces"}}),
                    &endpoint,
                    &from,
                )
                .await
            }
        };
        call(&a, &ea, "B").await.unwrap();
        call(&b, &eb, "A").await.unwrap();
        let a_to_b = a.peers.outbound.kept(eb.id()).unwrap();
        assert!(b.peers.outbound.kept(ea.id()).is_some());
        assert!(
            a.peers
                .connections
                .lock()
                .contains_key(&eb.id().to_string())
        );
        assert!(
            b.peers
                .connections
                .lock()
                .contains_key(&ea.id().to_string())
        );
        // A revokes B. That closes B's connection into A, not A's own connection to B.
        admin(
            Admin::Revoke {
                endpoint_id: eb.id().to_string(),
            },
            None,
            &a,
        )
        .await
        .unwrap();
        assert!(a.peers.connections.lock().is_empty());
        call(&a, &ea, "B").await.unwrap();
        let kept = a.peers.outbound.kept(eb.id()).unwrap();
        assert_eq!(kept.stable_id(), a_to_b.stable_id());
        assert_eq!(
            call(&b, &eb, "A").await.unwrap_err(),
            "authorization_denied"
        );
        // A forgets B: its kept connection closes, and B releases it.
        admin(
            Admin::Forget {
                endpoint_id: eb.id().to_string(),
            },
            None,
            &a,
        )
        .await
        .unwrap();
        assert!(a.peers.outbound.kept(eb.id()).is_none());
        timeout(Duration::from_secs(3), a_to_b.closed())
            .await
            .unwrap();
        until(|| b.peers.connections.lock().is_empty()).await;
        drop((home_a, home_b));
        ea.close().await;
        eb.close().await;
    }

    #[tokio::test]
    async fn peer_destination_closes_a_kept_connection_only_when_idle() {
        let (_home, mut state, _, _, grant) = fixture().await;
        let lookup = iroh::address_lookup::memory::MemoryLookup::new();
        let host = endpoint(accepted_alpns(), iroh::SecretKey::generate(), &lookup).await;
        let client = endpoint(Vec::new(), iroh::SecretKey::generate(), &lookup).await;
        Arc::get_mut(&mut state).unwrap().host_endpoint_id = host.id();
        state
            .peers
            .change(|s| {
                s.incoming[0].peer.endpoint_id = client.id().to_string();
                Ok(())
            })
            .unwrap();
        let idle = Duration::from_millis(200);
        let server = tokio::spawn({
            let (host, state) = (host.clone(), state.clone());
            async move {
                for _ in 0..2 {
                    let connection = host.accept().await.unwrap().await.unwrap();
                    serve_within(connection, state.clone(), idle).await;
                }
            }
        });
        let list = req(&grant, Action::Workspaces {});
        let connection = client
            .connect(host.addr(), peers::ALPN_STREAMS)
            .await
            .unwrap();
        assert!(matches!(
            ask(&connection, &list).await,
            Sent::Answered(Ok(_))
        ));
        let answered = std::time::Instant::now();
        let closed = timeout(Duration::from_secs(5), connection.closed())
            .await
            .unwrap();
        assert!(answered.elapsed() >= idle);
        assert!(matches!(closed, ConnectionError::ApplicationClosed(close)
            if close.error_code == VarInt::from_u32(0) && &close.reason[..] == b"peer idle"));
        // A request in flight keeps the connection open past the idle period.
        let connection = client
            .connect(host.addr(), peers::ALPN_STREAMS)
            .await
            .unwrap();
        until(|| !state.peers.connections.lock().is_empty()).await;
        let gate = state.peers.effects.lock().await;
        let pending = tokio::spawn({
            let (connection, list) = (connection.clone(), list.clone());
            async move { matches!(ask(&connection, &list).await, Sent::Answered(Ok(_))) }
        });
        tokio::time::sleep(idle * 3).await;
        assert!(connection.close_reason().is_none());
        drop(gate);
        assert!(pending.await.unwrap());
        timeout(Duration::from_secs(5), connection.closed())
            .await
            .unwrap();
        server.await.unwrap();
        assert!(state.peers.connections.lock().is_empty());
        client.close().await;
        host.close().await;
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
                scope: GrantScope::Selected(ids.clone()),
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
                    agent: PeerAgent::Claude,
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

    /// A deterministic vendor subprocess. It asserts the actual launch cwd and writes
    /// commands to the test workspace so this covers the app-server transport as well.
    fn install_codex_fixture(paths: &CiaoPaths) {
        use std::os::unix::fs::PermissionsExt;
        let binary = paths.home.join(".local/bin/codex-fixture");
        fs::create_dir_all(binary.parent().unwrap()).unwrap();
        let script = r#"#!/usr/bin/python3
import json, os, sys, uuid
if sys.argv[1:] == ["--version"]:
    print("codex-cli TESTED_VERSION")
    sys.exit()
assert sys.argv[1:] == ["app-server"]
thread = str(uuid.uuid4())
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    method = msg["method"]
    params = msg.get("params", {})
    result = {}
    if method == "thread/start":
        assert os.path.samefile(params["cwd"], os.getcwd())
        assert set(params) == {"cwd"}
        result = {"thread": {"id": thread, "path": os.path.join(os.getcwd(), "rollout"), "turns": []}}
    elif method == "turn/start":
        assert params["threadId"] == thread
        with open("received", "a") as received:
            print(params["input"][0]["text"], file=received)
        result = {"turn": {"id": "t", "status": "inProgress"}}
    print(json.dumps({"id": msg["id"], "result": result}), flush=True)
"#;
        fs::write(
            &binary,
            script.replace("TESTED_VERSION", crate::codex_adapter::PINNED_CODEX_VERSION),
        )
        .unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        let evidence = crate::codex_adopted::runtime_file(paths);
        fs::create_dir_all(evidence.parent().unwrap()).unwrap();
        fs::write(evidence, json!({"binary":binary}).to_string()).unwrap();
    }

    #[tokio::test]
    async fn peer_native_codex_launch_command_stop_and_ownership() {
        let (_temp, state, source, ids, grant) = fixture().await;
        install_codex_fixture(&state.paths);
        let call = |action| execute(source, req(&grant, action), &state);
        let launch = Action::Start {
            agent: PeerAgent::Codex,
            request_id: "new".into(),
            workspace_id: ids[0].clone(),
        };
        let first = call(launch.clone()).await.unwrap();
        assert_eq!(first["state"], "accepted", "{first}");
        assert_eq!(call(launch).await.unwrap(), first);
        let session = first["session_id"].as_str().unwrap().to_owned();
        let generation = first["process_generation"].as_u64().unwrap();
        assert_eq!(
            call(Action::Start {
                agent: PeerAgent::Claude,
                request_id: "new".into(),
                workspace_id: ids[0].clone()
            })
            .await
            .unwrap_err(),
            "request_id_reused"
        );
        let get = Action::Snapshot {
            session_id: session.clone(),
        };
        let snapshot = call(get.clone()).await.unwrap();
        assert_eq!(snapshot["adapter"]["family"], "Codex");
        let thread = state.codex_adoptions.thread_for_session(&session).unwrap();
        state.codex_adoptions.request_release(
            &thread,
            crate::codex_adopted::ReleaseReason::ConversationClosed,
        );
        let send = Action::Command {
            command: AgentCommand {
                v: 1,
                command_id: "prompt".into(),
                session_id: session.clone(),
                snapshot_epoch: snapshot["snapshot_epoch"].as_u64().unwrap(),
                expected_generation: generation,
                expected_revision: None,
                kind: AgentCommandKind::Prompt {
                    text: "fixture task".into(),
                },
            },
        };
        let (_, mut updates) = state
            .agent_sessions
            .subscribe_from_snapshot(&session)
            .unwrap();
        call(send.clone()).await.unwrap();
        let path = state
            .managed_sessions
            .resolve_workspace(&ids[0])
            .await
            .unwrap()
            .0
            .join("received");
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if state
                    .agent_sessions
                    .snapshot(&session)
                    .unwrap()
                    .latest_command_receipts
                    .iter()
                    .any(|receipt| receipt.state == "applied")
                {
                    break;
                }
                updates.recv().await.unwrap();
            }
        })
        .await
        .unwrap();
        call(send.clone()).await.unwrap();
        start(&state, source, &grant, "claude", &ids[1]).await;
        assert_eq!(
            call(Action::Start {
                agent: PeerAgent::Codex,
                request_id: "third".into(),
                workspace_id: ids[0].clone()
            })
            .await
            .unwrap_err(),
            "worker_limit"
        );
        admin(
            update(source, GrantScope::Selected(vec![ids[1].clone()])),
            None,
            &state,
        )
        .await
        .unwrap();
        assert_eq!(call(get.clone()).await.unwrap_err(), "authorization_denied");
        admin(update(source, GrantScope::All), None, &state)
            .await
            .unwrap();
        let stop = Action::Stop {
            session_id: session.clone(),
            request_id: "stop".into(),
            expected_generation: generation,
        };
        assert_eq!(
            call(Action::Stop {
                session_id: session.clone(),
                request_id: "wrong".into(),
                expected_generation: generation + 1
            })
            .await
            .unwrap()["reason_code"],
            "stale_generation"
        );
        let stopped = call(stop.clone()).await.unwrap();
        assert_eq!(stopped["state"], "accepted");
        assert_eq!(call(stop).await.unwrap(), stopped);
        assert!(state.codex_adoptions.peer_sessions().is_empty());
        assert_eq!(fs::read_to_string(path).unwrap(), "fixture task\n");
        let receipt = Action::StopReceipt {
            session_id: session.clone(),
            request_id: "stop".into(),
        };
        assert_eq!(call(receipt.clone()).await.unwrap(), stopped);
        let cold = super::super::tests::test_state(
            state.host_endpoint_id,
            &_temp.path().join("paired.json"),
        );
        assert_eq!(
            execute(source, req(&grant, receipt), &cold).await.unwrap(),
            stopped
        );
        assert_eq!(
            execute(source, req(&grant, get.clone()), &cold)
                .await
                .unwrap_err(),
            "session_stopped"
        );
        let legacy: Value =
            serde_json::from_slice(&fs::read(_temp.path().join("peers.json")).unwrap()).unwrap();
        let reservation = legacy["starts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["request_id"] == "new")
            .unwrap();
        assert!(reservation.get("agent").is_none() && reservation.get("stop_request").is_none());
        assert_eq!(reservation["outcome"]["state"], "refused");
        assert!(reservation["outcome"].get("session_id").is_none());
        // A new generation with the same stable ID is under the person's control.
        let _human = register(&state, &session).await;
        assert_eq!(call(get).await.unwrap_err(), "session_stopped");
        let mut new_command = match send {
            Action::Command { command } => command,
            _ => unreachable!(),
        };
        new_command.expected_generation = state
            .agent_sessions
            .snapshot(&session)
            .unwrap()
            .process_generation;
        assert_eq!(
            call(Action::Command {
                command: new_command
            })
            .await
            .unwrap_err(),
            "session_stopped"
        );
    }

    #[tokio::test]
    async fn peer_codex_handback_fences_the_later_human_writer() {
        let (_temp, state, source, ids, grant) = fixture().await;
        install_codex_fixture(&state.paths);
        let call = |action| execute(source, req(&grant, action), &state);
        let first = call(Action::Start {
            agent: PeerAgent::Codex,
            request_id: "new".into(),
            workspace_id: ids[0].clone(),
        })
        .await
        .unwrap();
        let session = first["session_id"].as_str().unwrap();
        let worker = state.codex_adoptions.peer_worker(session).unwrap();
        worker
            .send(crate::codex_adopted::ReleaseReason::ResumeInTerminal)
            .await
            .unwrap();
        worker.closed().await;
        let _human = register(&state, session).await;
        let human = state.agent_sessions.snapshot(session).unwrap();
        assert_ne!(
            Some(human.process_generation),
            first["process_generation"].as_u64()
        );
        assert_eq!(
            call(Action::Snapshot {
                session_id: session.into()
            })
            .await
            .unwrap_err(),
            "session_unavailable"
        );
        let command = AgentCommand {
            v: 1,
            command_id: "new-turn".into(),
            session_id: session.into(),
            snapshot_epoch: human.snapshot_epoch,
            expected_generation: human.process_generation,
            expected_revision: None,
            kind: AgentCommandKind::Prompt {
                text: "test".into(),
            },
        };
        assert_eq!(
            call(Action::Command { command }).await.unwrap_err(),
            "session_unavailable"
        );
        let stop = Action::Stop {
            session_id: session.into(),
            request_id: "later".into(),
            expected_generation: human.process_generation,
        };
        assert_eq!(call(stop).await.unwrap()["reason_code"], "stale_generation");
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
                        agent: PeerAgent::Claude,
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
                        agent: PeerAgent::Claude,
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
                        agent: PeerAgent::Claude,
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

    fn update(source: EndpointId, scope: GrantScope) -> Admin {
        Admin::Update {
            endpoint_id: source.to_string(),
            scope,
        }
    }

    #[tokio::test]
    async fn peer_update_changes_scope_in_place_and_narrowing_fences_removed_projects() {
        let (_temp, state, source, ids, grant) = fixture().await;
        let first = start(&state, source, &grant, "in-alpha", &ids[0]).await;
        assert_eq!(first["state"], "accepted");
        let sid = first["session_id"].as_str().unwrap().to_owned();
        let _receiver = register(&state, &sid).await;
        let snapshot = |sid: String| {
            let state = state.clone();
            let request = req(&grant, Action::Snapshot { session_id: sid });
            async move { execute(source, request, &state).await }
        };
        assert!(snapshot(sid.clone()).await.is_ok());

        // Narrow to beta only: the grant and its ID survive, alpha's session is fenced.
        admin(
            update(source, GrantScope::Selected(vec![ids[1].clone()])),
            None,
            &state,
        )
        .await
        .unwrap();
        let kept = state.peers.incoming(source, None).unwrap();
        assert_eq!(kept.grant_id, grant, "an edit must not mint a new grant");
        assert_eq!(kept.scope, GrantScope::Selected(vec![ids[1].clone()]));
        assert_eq!(
            snapshot(sid.clone()).await.unwrap_err(),
            "authorization_denied"
        );
        assert_eq!(
            execute(
                source,
                req(
                    &grant,
                    Action::Start {
                        agent: PeerAgent::Claude,
                        request_id: "alpha-again".into(),
                        workspace_id: ids[0].clone()
                    }
                ),
                &state
            )
            .await
            .unwrap_err(),
            "authorization_denied"
        );
        let listed = execute(source, req(&grant, Action::Workspaces {}), &state)
            .await
            .unwrap();
        assert_eq!(listed["workspaces"].as_array().unwrap().len(), 1);
        assert_eq!(
            state.managed_sessions.live_count(),
            1,
            "narrowing never stops a running worker"
        );

        // Widen again: the same grant regains its own session.
        admin(
            update(source, GrantScope::Selected(ids.clone())),
            None,
            &state,
        )
        .await
        .unwrap();
        assert!(snapshot(sid).await.is_ok());

        // An ID that is neither granted nor discoverable is refused; a stale granted ID is not.
        assert_eq!(
            admin(
                update(source, GrantScope::Selected(vec!["0".repeat(32)])),
                None,
                &state
            )
            .await
            .unwrap_err(),
            "unknown_workspace"
        );
        state
            .peers
            .change(|s| {
                s.incoming[0].scope = GrantScope::Selected(vec![ids[0].clone(), "f".repeat(32)]);
                Ok(())
            })
            .unwrap();
        admin(
            update(
                source,
                GrantScope::Selected(vec![ids[1].clone(), "f".repeat(32)]),
            ),
            None,
            &state,
        )
        .await
        .expect("re-saving a granted ID discovery no longer lists must succeed");
        // Leaving All for a selection names only IDs the host can resolve now.
        admin(update(source, GrantScope::All), None, &state)
            .await
            .unwrap();
        assert_eq!(
            admin(
                update(source, GrantScope::Selected(vec!["f".repeat(32)])),
                None,
                &state
            )
            .await
            .unwrap_err(),
            "unknown_workspace"
        );
        let stranger = iroh::SecretKey::generate().public();
        assert_eq!(
            admin(update(stranger, GrantScope::All), None, &state)
                .await
                .unwrap_err(),
            "not_linked"
        );
        for scope in [
            GrantScope::Selected(vec![]),
            GrantScope::Selected(vec![peers::ALL_WORKSPACES.into(), ids[0].clone()]),
        ] {
            assert_eq!(
                admin(update(source, scope), None, &state)
                    .await
                    .unwrap_err(),
                "unknown_workspace"
            );
        }
    }

    #[tokio::test]
    async fn peer_all_projects_covers_every_resolvable_workspace_including_later_ones() {
        let (temp, state, source, ids, grant) = fixture().await;
        admin(update(source, GrantScope::All), None, &state)
            .await
            .unwrap();
        // A checkout created after the grant is covered without another edit.
        fs::create_dir_all(temp.path().join("gamma").join(".git")).unwrap();
        let listed = execute(source, req(&grant, Action::Workspaces {}), &state)
            .await
            .unwrap();
        let listed: Vec<_> = listed["workspaces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| w["workspace_id"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(listed.len(), 3);
        let gamma = listed.iter().find(|id| !ids.contains(id)).unwrap().clone();
        let started = start(&state, source, &grant, "in-gamma", &gamma).await;
        assert_eq!(started["state"], "accepted");
        // Anything the host cannot resolve is refused by the launcher, never treated as a path.
        let unknown = start(&state, source, &grant, "nowhere", &"0".repeat(32)).await;
        assert_eq!(unknown["reason_code"], "unknown_workspace");

        // Persisted and described inside the existing list, so 0.1.61 and older apps still parse
        // it: one reserved ID that their checks accept and that matches no real workspace.
        let stored: Value =
            serde_json::from_slice(&fs::read(temp.path().join("peers.json")).unwrap()).unwrap();
        assert_eq!(stored["incoming"][0]["workspace_ids"], json!(["all"]));
        assert!(peers::valid_id(peers::ALL_WORKSPACES));
        assert!(!ids.iter().any(|id| id == peers::ALL_WORKSPACES));
        let description = admin(Admin::Describe {}, None, &state).await.unwrap();
        assert_eq!(description["incoming"][0]["workspace_ids"], json!(["all"]));
        assert_eq!(description["admin_revision"], 2);

        // A new grant can be all-projects from the start.
        let other = iroh::SecretKey::generate().public();
        admin(
            Admin::Grant {
                peer: Descriptor {
                    endpoint_id: other.to_string(),
                    name: "Other".into(),
                },
                scope: GrantScope::All,
            },
            None,
            &state,
        )
        .await
        .unwrap();
        assert_eq!(
            state.peers.incoming(other, None).unwrap().scope,
            GrantScope::All
        );
    }

    #[tokio::test]
    async fn peer_revoke_and_forget_each_remove_one_direction_and_remember_replaces() {
        let (_temp, state, source, _ids, grant) = fixture().await;
        let remember = |grant_id: &str| Admin::Remember {
            link: Outgoing {
                peer: Descriptor {
                    endpoint_id: source.to_string(),
                    name: "Source".into(),
                },
                grant_id: grant_id.into(),
            },
        };
        // This host also sends work to the source: the reverse direction.
        admin(remember("reverse-one"), None, &state).await.unwrap();
        // A second introduction replaces the stale link instead of refusing as `already_linked`.
        admin(remember("reverse-two"), None, &state).await.unwrap();
        let store = state.peers.snapshot();
        assert_eq!(store.outgoing.len(), 1);
        assert_eq!(store.outgoing[0].grant_id, "reverse-two");

        admin(
            Admin::Revoke {
                endpoint_id: source.to_string(),
            },
            None,
            &state,
        )
        .await
        .unwrap();
        let store = state.peers.snapshot();
        assert!(store.incoming.is_empty());
        assert_eq!(
            store.outgoing.len(),
            1,
            "revoking the source's access must keep this host's own link to it"
        );
        assert_eq!(
            execute(source, req(&grant, Action::Workspaces {}), &state)
                .await
                .unwrap_err(),
            "authorization_denied"
        );

        admin(
            Admin::Forget {
                endpoint_id: source.to_string(),
            },
            None,
            &state,
        )
        .await
        .unwrap();
        assert!(state.peers.snapshot().outgoing.is_empty());
    }

    #[tokio::test]
    async fn peer_description_lists_granted_projects_before_the_cap() {
        let (_temp, state, source, _ids, _grant) = fixture().await;
        let workspaces: Vec<_> = (0..peers::MAX_WORKSPACES + 8)
            .map(|i| agent_protocol::WorkspaceDescriptor {
                workspace_id: format!("{i:032x}"),
                display_label: format!("Project {i}"),
            })
            .collect();
        let granted = vec![format!("{:032x}", peers::MAX_WORKSPACES + 5)];
        let mut store = state.peers.snapshot();
        store.incoming[0].scope = GrantScope::Selected(granted.clone());
        assert_eq!(store.incoming[0].peer.endpoint_id, source.to_string());
        let projects = agent_protocol::AgentWorkspaceList {
            v: 1,
            message_type: "agent_workspace_list".into(),
            workspaces,
            omitted_workspaces: 0,
            scan_incomplete: false,
        };
        let result = description_result(&state, store, projects).unwrap();
        let listed = result["workspaces"].as_array().unwrap();
        assert_eq!(listed.len(), peers::MAX_WORKSPACES);
        assert_eq!(listed[0]["workspace_id"], granted[0]);
        assert_eq!(listed[1]["workspace_id"], format!("{:032x}", 0));
        assert_eq!(result["scan_incomplete"], true);
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
                scope: GrantScope::Selected(ids),
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
                    agent: PeerAgent::Claude,
                    stop_request: None,
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
                        agent: PeerAgent::Claude,
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
                    scope: GrantScope::Selected(ids)
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
                        scope: GrantScope::Selected(vec!["workspace".into()]),
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
                    agent: PeerAgent::Claude,
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
                scope: GrantScope::Selected(workspace_ids.clone()),
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
