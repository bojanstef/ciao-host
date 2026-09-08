//! Internal boundary between attached vendor integrations and Ciao's normalized Agent Sessions.
//!
//! Adapter-specific wire values stop at implementations of [`AttachedAgentAdapter`]. The daemon
//! and session supervisor consume only the normalized registration/events below and emit only
//! canonical Ciao commands. This boundary deliberately says nothing about how a future adapter
//! observes its vendor; a long-lived extension bridge is only one possible integration topology.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    agent_protocol::{
        AgentCapabilities, AgentCommand, AgentProtocolError, CommandCapabilities,
        InteractionCapabilities, Observation, PendingInteraction, TimelineBody, Truncation,
        TurnState, classify_vendor_version, valid_opaque_id, valid_token,
    },
    agent_session::{
        NormalizedRegistration, NormalizedTextDelta, NormalizedTimelineEntry,
        RegisteredAgentSession,
    },
};

/// Fixed capacity for a live adapter's canonical command channel.
pub(crate) const ADAPTER_COMMAND_CHANNEL_CAPACITY: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdapterConnectionKind {
    PersistentBridge,
    TransientEvent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NormalizedAdapterEvent {
    Registration,
    SnapshotStart,
    SnapshotEntry(NormalizedTimelineEntry),
    SnapshotEnd,
    UpsertEntry(NormalizedTimelineEntry),
    AppendText(NormalizedTextDelta),
    Heartbeat,
    SessionEnded,
    CommandCapabilities(CommandCapabilities),
    /// The permission mode the adapter is now running under. Session-level, and reported by
    /// the adapter rather than assumed from what Ciao last asked for: a mode can also be
    /// changed at the vendor's own end, and the session's own word is the only truthful source.
    PermissionMode(String),
    /// The model now answering, as the adapter observed it rather than as Ciao requested it.
    /// Same rule as the mode above, and the same reason: the vendor can change this out from
    /// under a request, and only the session's own report is worth showing.
    Model(String),
    /// The reasoning effort in force, reported only when actually known.
    Effort(String),
    /// The models this session can switch to, read from the running adapter. Sent whole,
    /// because a menu is only ever correct as a complete set.
    ModelCatalogue(Vec<crate::agent_protocol::AgentModelOption>),
    CommandReceipt {
        command_id: String,
        state: String,
        evidence: Option<String>,
        reason_code: Option<String>,
    },
    /// The managed worker's real vendor session ID, reported once its first
    /// turn creates one. Until then the session has no vendor session at all.
    VendorSession(String),
    /// An adapter that can see its own turn boundaries saying one changed. Session-level, and
    /// the only sanctioned source of "working": Ciao never infers it from timing or output.
    Turn(TurnState),
    /// A blocking interaction raised by a managed worker (Spec 006 §9.5).
    UpsertInteraction(Box<PendingInteraction>),
    /// The worker's authoritative single resolution of one interaction.
    ResolveInteraction {
        interaction_id: String,
        resolution: String,
    },
    Shutdown {
        process_exited: bool,
    },
    /// The session wants its human, and the vendor's own reason for saying so
    /// (`permission_prompt`, `idle_prompt`, …). Session-level, never timeline content.
    Notification(String),
    Unknown,
}

/// A bounded adapter-specific codec selected by the local bridge registry.
///
/// Implementations validate and normalize vendor-owned bridge frames. Returning JSON for outbound
/// values keeps serialization behind the adapter boundary without exposing a generic invocation
/// surface: the input is still one fixed canonical Ciao command.
pub(crate) trait AttachedAgentAdapter: Send + Sync {
    /// Stable machine token used only for local bridge dispatch, never as a capability shortcut.
    fn id(&self) -> &'static str;

    fn connection_kind(&self) -> AdapterConnectionKind {
        AdapterConnectionKind::PersistentBridge
    }

    fn requires_tui_process(&self) -> bool {
        false
    }

    /// Temporary compatibility for a bridge registration written before explicit adapter dispatch
    /// was introduced. Only a codec that can validate the complete legacy shape may opt in.
    fn accepts_legacy_registration(&self) -> bool {
        false
    }

    fn decode_registration(
        &self,
        body: &[u8],
        peer_process_id: Option<u32>,
    ) -> Result<NormalizedRegistration, AgentProtocolError>;

    fn decode_event(&self, body: &[u8]) -> Result<NormalizedAdapterEvent, AgentProtocolError>;

    fn registered_frame(
        &self,
        session: &RegisteredAgentSession,
    ) -> Result<Value, AgentProtocolError>;

    fn command_frame(&self, command: AgentCommand) -> Result<Value, AgentProtocolError>;

    fn event_applied_frame(&self) -> Result<Option<Value>, AgentProtocolError> {
        Ok(None)
    }

    fn shutdown_frame(&self, reason_code: &str) -> Result<Value, AgentProtocolError>;
}

/// One timeline entry as every dialect spells it on the wire. Four field-identical copies of
/// this struct used to live in the four adapter modules; what keeps a dialect's vocabulary
/// distinct is which frames it decodes, not how an entry payload is shaped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireTimelineEntry {
    pub source_id: String,
    pub source_revision: u64,
    pub timestamp: u64,
    pub state: String,
    pub kind: String,
    pub body: TimelineBody,
    pub truncation: Truncation,
}

impl WireTimelineEntry {
    pub(crate) fn normalize(self) -> Result<NormalizedTimelineEntry, AgentProtocolError> {
        let entry = NormalizedTimelineEntry {
            source_id: self.source_id,
            source_revision: self.source_revision,
            timestamp: self.timestamp,
            state: self.state,
            kind: self.kind,
            body: self.body,
            truncation: self.truncation,
        };
        entry.validate()?;
        Ok(entry)
    }
}

/// One streamed text delta as the dialects that stream spell it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WireTextDelta {
    pub source_id: String,
    pub source_revision: u64,
    pub timestamp: u64,
    pub kind: String,
    pub delta: String,
    pub final_chunk: bool,
    pub truncation: Truncation,
}

impl WireTextDelta {
    pub(crate) fn normalize(self) -> Result<NormalizedTextDelta, AgentProtocolError> {
        let delta = NormalizedTextDelta {
            source_id: self.source_id,
            source_revision: self.source_revision,
            timestamp: self.timestamp,
            kind: self.kind,
            delta: self.delta,
            final_chunk: self.final_chunk,
            truncation: self.truncation,
        };
        delta.validate()?;
        Ok(delta)
    }
}

pub(crate) fn validate_frame_header(
    version: u8,
    protocol_version: u8,
    actual: &str,
    expected: &str,
) -> Result<(), AgentProtocolError> {
    if version != protocol_version {
        return Err(AgentProtocolError::UnsupportedVersion);
    }
    if actual != expected {
        return Err(AgentProtocolError::UnexpectedMessage);
    }
    Ok(())
}

pub(crate) fn decode_unit_frame(
    value: &Value,
    protocol_version: u8,
    expected: &str,
) -> Result<(), AgentProtocolError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Frame {
        v: u8,
        #[serde(rename = "type")]
        message_type: String,
    }
    let frame: Frame =
        serde_json::from_value(value.clone()).map_err(|_| AgentProtocolError::MalformedJson)?;
    validate_frame_header(frame.v, protocol_version, &frame.message_type, expected)
}

pub(crate) fn decode_entry_frame(
    value: Value,
    protocol_version: u8,
    expected: &str,
) -> Result<WireTimelineEntry, AgentProtocolError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Frame {
        v: u8,
        #[serde(rename = "type")]
        message_type: String,
        entry: WireTimelineEntry,
    }
    let frame: Frame =
        serde_json::from_value(value).map_err(|_| AgentProtocolError::MalformedJson)?;
    validate_frame_header(frame.v, protocol_version, &frame.message_type, expected)?;
    Ok(frame.entry)
}

pub(crate) fn decode_delta_frame(
    value: Value,
    protocol_version: u8,
) -> Result<WireTextDelta, AgentProtocolError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Frame {
        v: u8,
        #[serde(rename = "type")]
        message_type: String,
        delta: WireTextDelta,
    }
    let frame: Frame =
        serde_json::from_value(value).map_err(|_| AgentProtocolError::MalformedJson)?;
    validate_frame_header(
        frame.v,
        protocol_version,
        &frame.message_type,
        "append_text",
    )?;
    Ok(frame.delta)
}

pub(crate) fn decode_notification_frame(
    value: Value,
    protocol_version: u8,
) -> Result<String, AgentProtocolError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Frame {
        v: u8,
        #[serde(rename = "type")]
        message_type: String,
        kind: String,
    }
    let frame: Frame =
        serde_json::from_value(value).map_err(|_| AgentProtocolError::MalformedJson)?;
    validate_frame_header(
        frame.v,
        protocol_version,
        &frame.message_type,
        "notification",
    )?;
    valid_token(&frame.kind)?;
    Ok(frame.kind)
}

/// The turn edge an attached hook reports, spelled as a nested [`TurnState`].
///
/// Shared because two dialects send it identically. Pi and the managed worker flatten the state
/// onto the frame itself and keep their own decoders; a hook has one event per connection and
/// nothing to flatten around, so `codex` and `claude` send the canonical shape and read it here.
/// The state is validated rather than trusted: a `running` with no run to point at is refused,
/// not degraded into something harmless.
pub(crate) fn decode_turn_frame(
    value: Value,
    protocol_version: u8,
) -> Result<TurnState, AgentProtocolError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Frame {
        v: u8,
        #[serde(rename = "type")]
        message_type: String,
        turn: TurnState,
    }
    let frame: Frame =
        serde_json::from_value(value).map_err(|_| AgentProtocolError::MalformedJson)?;
    validate_frame_header(frame.v, protocol_version, &frame.message_type, "turn")?;
    frame.turn.validate()?;
    Ok(frame.turn)
}

/// What distinguishes one attached-hook dialect at registration: the tokens and the reason
/// codes. Everything else about an attached hook registration is shared shape, so a fix to it
/// lands for every dialect or for none.
pub(crate) struct AttachedHookDialect {
    pub(crate) adapter: &'static str,
    pub(crate) family: &'static str,
    pub(crate) pinned_version: &'static str,
    /// The dialect's prover, when one exists (Spec 017 §4.3): asked only after the classifier
    /// refuses, and answering `true` means independently gathered evidence covers this exact
    /// version — the state becomes `carried` rather than `unsupported`. Codex points this at
    /// its schema-extract verdict; Claude has nothing to interrogate and leaves it `None`.
    pub(crate) carry: Option<fn(&str) -> bool>,
    pub(crate) protocol_version: u8,
    /// Observation reason when a supported build registers.
    pub(crate) partial_reason: &'static str,
    /// Turn reason on a supported / unsupported build. Both attached dialects name their own
    /// turns, so a supported build says which one is unreported and an unsupported one says the
    /// version is why.
    pub(crate) turn_reason_supported: &'static str,
    pub(crate) turn_reason_unsupported: &'static str,
}

/// The registration frame every attached hook dialect sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AttachedHookRegister {
    pub v: u8,
    #[serde(rename = "type")]
    pub message_type: String,
    pub adapter: String,
    pub adapter_version: String,
    pub mode: String,
    pub session_id: String,
    pub process_nonce: String,
    pub process_id: u32,
    pub workspace_display: String,
    /// The session's absolute working directory. Host-only: promotion needs somewhere to
    /// launch a managed worker, and a basename cannot say where that is. It is never copied
    /// into a descriptor, so it does not reach iOS.
    pub workspace_path: String,
}

impl AttachedHookRegister {
    pub(crate) fn normalize(
        self,
        peer_process_id: Option<u32>,
        dialect: &AttachedHookDialect,
    ) -> Result<NormalizedRegistration, AgentProtocolError> {
        if self.v != dialect.protocol_version
            || self.message_type != "register"
            || self.adapter != dialect.adapter
            || self.mode != "tui_hook"
            || self.process_id == 0
            || peer_process_id.is_none()
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        valid_opaque_id(&self.session_id)?;
        valid_opaque_id(&self.process_nonce)?;
        valid_token(&self.adapter_version)?;
        if self.workspace_display.is_empty() || self.workspace_display.len() > 256 {
            return Err(AgentProtocolError::InvalidValue);
        }
        // Spec 017 §3: one classifier for the install path, the hook path, and this
        // registration — the policy doc's trap #1 demands they never diverge. The pin's own
        // major decides whether a later minor is admitted as `ahead` (2.x Claude) or refused
        // (0.x Codex), so the two dialects share this line without per-dialect configuration.
        let mut state = classify_vendor_version(&self.adapter_version, dialect.pinned_version);
        // A prover is only ever asked about the band it can honestly speak for: a later minor
        // of the tested major. The shell enforces the band so no prover — present or future —
        // can vouch a major or a below-floor build into admission.
        if state == crate::agent_protocol::VendorVersionState::Unsupported
            && crate::agent_protocol::later_minor_of_tested_major(
                &self.adapter_version,
                dialect.pinned_version,
            )
            && let Some(carry) = dialect.carry
            && carry(&self.adapter_version)
        {
            state = crate::agent_protocol::VendorVersionState::Carried;
        }
        let compatible = state.admitted();
        Ok(NormalizedRegistration {
            history_boundary: None,
            upstream_identity: self.session_id,
            process_nonce: self.process_nonce,
            process_id: self.process_id,
            adapter_family: dialect.family.into(),
            adapter_version: self.adapter_version,
            topology: "attached".into(),
            compatible,
            version_state: state.token().into(),
            tested_version: dialect.pinned_version.into(),
            workspace_display: self.workspace_display,
            // Only an absolute directory is usable as a launch target; anything else is
            // dropped rather than carried as a value promotion would later have to refuse.
            workspace_path: std::path::Path::new(&self.workspace_path)
                .is_absolute()
                .then_some(self.workspace_path),
            observation: Observation {
                coverage: "partial".into(),
                reason_code: if compatible {
                    dialect.partial_reason
                } else {
                    "adapter_version_unsupported"
                }
                .into(),
                last_authoritative_at: None,
            },
            // A registration never states a turn. Spec 005 §1 makes turn provenance structural
            // rather than validated — "no registration path produces a `running` turn" — and
            // `NormalizedRegistration::validate` enforces it by refusing a working turn from a
            // partially-observed session. Turns travel as their own events, from the dialects
            // that can see them.
            turn: TurnState::Unknown {
                reason_code: if compatible {
                    dialect.turn_reason_supported
                } else {
                    dialect.turn_reason_unsupported
                }
                .into(),
            },
            capabilities: AgentCapabilities {
                history: "live_tail".into(),
                commands: CommandCapabilities::none(),
                interactions: InteractionCapabilities::none(),
                pending_rehydration: "none".into(),
                terminal_continuity: "unavailable".into(),
            },
            control_owner: "terminal".into(),
        })
    }
}

/// The service frames every attached hook dialect answers with — identical across dialects by
/// construction now, instead of by two copies staying identical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum AttachedHookOutbound {
    Registered {
        v: u8,
        session_id: String,
        process_generation: u64,
        snapshot_epoch: u64,
    },
    EventApplied {
        v: u8,
    },
    Shutdown {
        v: u8,
        reason_code: String,
    },
}

impl AttachedHookOutbound {
    pub(crate) fn registered_frame(
        session: &RegisteredAgentSession,
        protocol_version: u8,
    ) -> Result<Value, AgentProtocolError> {
        serde_json::to_value(Self::Registered {
            v: protocol_version,
            session_id: session.session_id.clone(),
            process_generation: session.process_generation,
            snapshot_epoch: session.snapshot_epoch,
        })
        .map_err(|_| AgentProtocolError::MalformedJson)
    }

    pub(crate) fn event_applied_frame(
        protocol_version: u8,
    ) -> Result<Option<Value>, AgentProtocolError> {
        serde_json::to_value(Self::EventApplied {
            v: protocol_version,
        })
        .map(Some)
        .map_err(|_| AgentProtocolError::MalformedJson)
    }

    pub(crate) fn shutdown_frame(
        reason_code: &str,
        protocol_version: u8,
    ) -> Result<Value, AgentProtocolError> {
        valid_token(reason_code)?;
        serde_json::to_value(Self::Shutdown {
            v: protocol_version,
            reason_code: reason_code.into(),
        })
        .map_err(|_| AgentProtocolError::MalformedJson)
    }
}

/// Splits one adapter frame into its dispatch token and body. The `type` field is the only
/// thing a dialect needs before choosing an arm.
pub(crate) fn frame_type(body: &[u8]) -> Result<(String, Value), AgentProtocolError> {
    let value: Value = crate::agent_protocol::decode_agent_body(body)?;
    let message_type = value
        .as_object()
        .and_then(|object| object.get("type"))
        .and_then(Value::as_str)
        .ok_or(AgentProtocolError::MalformedJson)?
        .to_owned();
    Ok((message_type, value))
}
