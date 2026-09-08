//! Managed Claude worker bridge wire (Spec 006 §9).
//!
//! The Ciao-owned worker runs the pinned Agent SDK on one side and speaks this
//! bounded local protocol on the other. SDK message types, vendor session
//! structures, transcript paths, and credentials never cross this boundary: the
//! worker maps them to canonical timeline entries, receipts, and interactions
//! before writing a frame.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    agent_adapter::{
        AttachedAgentAdapter, NormalizedAdapterEvent, WireTextDelta, WireTimelineEntry,
    },
    agent_protocol::{
        AgentCapabilities, AgentCommand, AgentCommandKind, AgentModelOption, AgentProtocolError,
        CommandCapabilities, InteractionCapabilities, InteractionCapability, Observation,
        PendingInteraction, ResponseSchema, TerminalFallback, TurnState, decode_agent_body,
        turn_from_bridge_frame, valid_model_id, valid_opaque_id, valid_token,
        validate_model_catalogue,
    },
    agent_session::{NormalizedRegistration, RegisteredAgentSession},
};

pub(crate) const PINNED_CLAUDE_SDK_VERSION: &str = "0.3.233";
/// The CLI the pinned SDK bundles, checked **exactly** — Ciao installs this pair itself into
/// its own prefix and SHA-256-verifies the binary before spawning it, so the version is one
/// Ciao chose rather than one the user's updater did. It ratchets forward with the SDK by
/// construction: each `0.3.N` wrapper manifest records bundled CLI `2.1.N`.
///
/// Separate from `PINNED_CLAUDE_VERSION`, which is the attached floor and must not move when
/// this does. They named the same value until 2026-08-16 only because the two pins happened to
/// be bumped together; the coupling was accidental and actively harmful.
pub(crate) const PINNED_MANAGED_CLI_VERSION: &str = "2.1.233";
pub(crate) const CLAUDE_MANAGED_PROTOCOL_VERSION: u8 = 1;

/// The pinned SDK's own `EffortLevel` union (`sdk.d.ts`), which lives here rather than in
/// `agent_protocol` for the reason spelled out beside `valid_model_id`: it is the vendor's list,
/// and this file is where the vendor pin already is. Ciao's protocol layer keeps model and
/// effort to grammar and bounds so a new vendor level cannot be blocked by a stale app, while
/// this adapter — which knows exactly which SDK it is talking to — refuses a level that pin
/// cannot do.
///
/// `max` is included: it is session-scoped and reachable through `applyFlagSettings`, even
/// though the *persistable* `Settings.effortLevel` excludes it.
pub(crate) const PINNED_EFFORT_LEVELS: [&str; 5] = ["low", "medium", "high", "xhigh", "max"];

pub(crate) struct ClaudeManagedAdapter;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClaudeManagedRegister {
    pub v: u8,
    #[serde(rename = "type")]
    pub message_type: String,
    pub adapter: String,
    pub adapter_version: String,
    pub sdk_version: String,
    /// One-time token minted by the launcher and delivered privately.
    pub spawn_token: String,
    /// Ciao session ID the launcher assigned before spawning.
    pub session_id: String,
    pub process_nonce: String,
    pub process_id: u32,
    pub workspace_display: String,
    /// Set when this worker resumed a conversation that already had turns. Absent from an
    /// older worker, and absent means "not resumed" — the state every worker was in before
    /// this field existed.
    #[serde(default)]
    pub resumed: bool,
    /// The worker read and mapped the complete bounded transcript before registration. Absent
    /// on the marker-only worker and false whenever the vendor file exceeds the reader bound.
    #[serde(default)]
    pub history_complete: bool,
}

impl ClaudeManagedRegister {
    fn normalize(
        self,
        peer_process_id: Option<u32>,
    ) -> Result<NormalizedRegistration, AgentProtocolError> {
        if self.v != CLAUDE_MANAGED_PROTOCOL_VERSION
            || self.message_type != "register"
            || self.adapter != "claude-managed"
            || self.process_id == 0
            || peer_process_id.is_none()
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        valid_opaque_id(&self.session_id)?;
        valid_opaque_id(&self.process_nonce)?;
        valid_opaque_id(&self.spawn_token)?;
        valid_token(&self.adapter_version)?;
        valid_token(&self.sdk_version)?;
        if self.workspace_display.is_empty() || self.workspace_display.len() > 256 {
            return Err(AgentProtocolError::InvalidValue);
        }
        // The pin covers CLI and SDK together; an unsupported pair advertises
        // nothing rather than degrading to best-effort messaging.
        let compatible = self.adapter_version == PINNED_MANAGED_CLI_VERSION
            && self.sdk_version == PINNED_CLAUDE_SDK_VERSION;
        Ok(NormalizedRegistration {
            history_boundary: (self.resumed && !self.history_complete).then(|| "resume".to_owned()),
            upstream_identity: self.session_id,
            process_nonce: self.process_nonce,
            process_id: self.process_id,
            adapter_family: "Claude".into(),
            adapter_version: self.adapter_version,
            // A managed worker is already daemon-owned and its workspace path is held in
            // the managed record, so nothing needs it echoed back through registration.
            workspace_path: None,
            topology: "managed".into(),
            compatible,
            // Exact pin: a managed runtime is never `ahead` — Ciao installed it, so drift is
            // impossible by construction and a mismatch is categorical.
            version_state: if compatible {
                "grounded"
            } else {
                "unsupported"
            }
            .into(),
            tested_version: PINNED_MANAGED_CLI_VERSION.into(),
            workspace_display: self.workspace_display,
            observation: Observation {
                coverage: if compatible {
                    "authoritative"
                } else {
                    "unavailable"
                }
                .into(),
                reason_code: if compatible {
                    "worker_stream"
                } else {
                    "adapter_version_unsupported"
                }
                .into(),
                last_authoritative_at: None,
            },
            turn: TurnState::Idle,
            capabilities: AgentCapabilities {
                // `full` is a per-session fact: the current worker advertises it only after the
                // documented reader mapped the entire transcript inside Ciao's fixed bounds.
                // An older worker, a failed read, or an over-bound transcript stays live-tail.
                history: if compatible && self.history_complete {
                    "full"
                } else {
                    "live_tail"
                }
                .into(),
                commands: if compatible {
                    // Capability order (Spec 006 §2.3): prompt and interrupt are
                    // conformance-backed; steer and follow-up are never advertised.
                    CommandCapabilities {
                        prompt: true,
                        steer: false,
                        follow_up: false,
                        interrupt: true,
                        // The SDK exposes `setPermissionMode` as a live control request, so
                        // this needs no respawn and is offered wherever the pin is supported.
                        permission_mode: true,
                        // Both are live control requests at this pin too — `setModel` for the
                        // model, `applyFlagSettings` for effort — so neither needs a respawn.
                        // Advertised together because the picker is one control, and gating
                        // them apart would mean a menu whose second half silently does nothing;
                        // the *per-model* effort gate is the catalogue's `supports_effort`,
                        // which is a fact about the chosen model rather than the adapter.
                        model: true,
                        effort: true,
                    }
                } else {
                    CommandCapabilities::none()
                },
                // Capability 3 of the Spec 006 §2.3 order. Grounded by the
                // permission probes: allow, deny, and fail-closed pendency with
                // abort-on-interrupt all pass at this pin. One request, one
                // choice; plan and review decisions stay disabled.
                //
                // The question bounds are the pinned SDK's own `AskUserQuestionInput`: one to
                // four questions, two to four options each. Free text is allowed because the
                // tool supplies an "Other" escape automatically, so a phone that could not
                // type would be answering a narrower question than the one asked.
                interactions: if compatible {
                    InteractionCapabilities {
                        permission: InteractionCapability {
                            enabled: true,
                            max_questions: 1,
                            max_options_per_question: 4,
                            allows_free_text: false,
                        },
                        question: InteractionCapability {
                            enabled: true,
                            max_questions: 4,
                            max_options_per_question: 4,
                            allows_free_text: true,
                        },
                        ..InteractionCapabilities::none()
                    }
                } else {
                    InteractionCapabilities::none()
                },
                pending_rehydration: if compatible {
                    "current_process"
                } else {
                    "none"
                }
                .into(),
                terminal_continuity: "unavailable".into(),
            },
            // A managed worker has no terminal owner; the reducer refuses any
            // other value for this topology.
            control_owner: "none".into(),
        })
    }
}

/// A permission request the worker is blocked on. Choice IDs are host-issued
/// opaque tokens; the worker resolves the SDK callback with exactly the choice
/// the user selected and never invents an Allow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClaudeManagedInteraction {
    pub interaction_id: String,
    pub interaction_revision: u64,
    pub kind: String,
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub body: String,
    pub response_schema: ResponseSchema,
}

impl ClaudeManagedInteraction {
    fn normalize(self) -> Result<PendingInteraction, AgentProtocolError> {
        // Permission, question and unsupported may be raised; a plan or review decision still
        // requires its own conformance. `question` is the worker's `AskUserQuestion` intercept,
        // and it is the one kind whose schema the phone answers question by question.
        if !matches!(
            self.kind.as_str(),
            "permission" | "question" | "unsupported"
        ) {
            return Err(AgentProtocolError::InvalidValue);
        }
        let interaction = PendingInteraction {
            interaction_id: self.interaction_id,
            interaction_revision: self.interaction_revision,
            kind: self.kind,
            blocking: true,
            created_at: self.created_at,
            expires_at: None,
            title: self.title,
            body: self.body,
            response_schema: self.response_schema,
            terminal_fallback: TerminalFallback {
                continuity: "unavailable".into(),
                route_id: None,
                availability_reason: Some("managed_headless".into()),
                handback_session: None,
                resume_command: None,
            },
            state: "pending".into(),
        };
        interaction.validate()?;
        Ok(interaction)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ClaudeManagedInbound {
    Register(ClaudeManagedRegister),
    Heartbeat,
    /// Spec 017 §4.2: the worker met a shape outside its pinned vocabulary and named it. A new
    /// frame type rather than a field on the heartbeat, deliberately: on a host too old to know
    /// it, an unknown *type* degrades to one unsupported card, where a heartbeat with an extra
    /// field would fail strict decode and kill the persistent worker stream.
    DriftNote {
        surface: String,
        name: String,
    },
    SnapshotStart,
    SnapshotEntry(WireTimelineEntry),
    SnapshotEnd,
    UpsertEntry(WireTimelineEntry),
    AppendText(WireTextDelta),
    CommandCapabilities {
        prompt: bool,
        interrupt: bool,
        permission_mode: bool,
        model: bool,
        effort: bool,
    },
    CommandReceipt {
        command_id: String,
        state: String,
        evidence: Option<String>,
        reason_code: Option<String>,
    },
    /// The real SDK session ID, learned when the worker's first turn begins.
    VendorSession(String),
    /// The mode the worker is running under, sent once it is up and again after any change.
    PermissionMode(String),
    /// The model actually answering, learned from the SDK rather than assumed from what was
    /// asked for. Sent when the worker first observes one and again after any accepted change.
    Model(String),
    /// The effort in force, sent only once it is genuinely known.
    Effort(String),
    /// What this account can switch to, read once from the SDK after registration.
    ModelCatalogue(Vec<AgentModelOption>),
    /// One edge of a turn, reported by the worker because only it can see them. Ciao never
    /// derives activity from output or elapsed time.
    Turn {
        state: String,
        run_id: Option<String>,
        activity: Option<String>,
    },
    UpsertInteraction(ClaudeManagedInteraction),
    ResolveInteraction {
        interaction_id: String,
        resolution: String,
    },
    /// The worker raised a blocking card and wants its human to hear about it. Session-level,
    /// never timeline content — the card itself travels as the interaction.
    Notification(String),
    SessionEnd,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ClaudeManagedOutbound {
    Registered {
        v: u8,
        session_id: String,
        process_generation: u64,
        snapshot_epoch: u64,
    },
    Command {
        v: u8,
        command_id: String,
        kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        text: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        interaction_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        choice_id: Option<String>,
        /// A question interaction's per-question answers. Exclusive with `choice_id`: a
        /// permission is one host-issued choice, a question is a set of them plus free text.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        answers: Option<Vec<crate::agent_protocol::QuestionAnswer>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mode: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        model: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        effort: Option<String>,
    },
    Shutdown {
        v: u8,
        reason_code: String,
    },
}

/// Explicit dispatch keeps each frame's field set strict: serde's internally
/// tagged representation consumes the `type` key, which a `deny_unknown_fields`
/// payload cannot reconstruct.
fn decode_managed_frame(body: &[u8]) -> Result<ClaudeManagedInbound, AgentProtocolError> {
    let value: Value = decode_agent_body(body)?;
    let object = value
        .as_object()
        .ok_or(AgentProtocolError::MalformedJson)?
        .clone();
    if object.get("v").and_then(Value::as_u64) != Some(u64::from(CLAUDE_MANAGED_PROTOCOL_VERSION)) {
        return Err(AgentProtocolError::UnsupportedVersion);
    }
    let message_type = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or(AgentProtocolError::MalformedJson)?
        .to_owned();
    let message_type = message_type.as_str();

    fn strict<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T, AgentProtocolError> {
        serde_json::from_value(value).map_err(|_| AgentProtocolError::MalformedJson)
    }
    fn unit(object: &serde_json::Map<String, Value>) -> Result<(), AgentProtocolError> {
        if object.len() == 2 {
            Ok(())
        } else {
            Err(AgentProtocolError::MalformedJson)
        }
    }

    Ok(match message_type {
        "register" => ClaudeManagedInbound::Register(strict(value)?),
        "heartbeat" => {
            unit(&object)?;
            ClaudeManagedInbound::Heartbeat
        }
        "snapshot_start" => {
            unit(&object)?;
            ClaudeManagedInbound::SnapshotStart
        }
        "snapshot_end" => {
            unit(&object)?;
            ClaudeManagedInbound::SnapshotEnd
        }
        "session_end" => {
            unit(&object)?;
            ClaudeManagedInbound::SessionEnd
        }
        "snapshot_entry" | "upsert_entry" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Frame {
                #[allow(dead_code)]
                v: u8,
                #[serde(rename = "type")]
                #[allow(dead_code)]
                message_type: String,
                entry: WireTimelineEntry,
            }
            let frame: Frame = strict(value)?;
            if message_type == "snapshot_entry" {
                ClaudeManagedInbound::SnapshotEntry(frame.entry)
            } else {
                ClaudeManagedInbound::UpsertEntry(frame.entry)
            }
        }
        "append_text" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Frame {
                #[allow(dead_code)]
                v: u8,
                #[serde(rename = "type")]
                #[allow(dead_code)]
                message_type: String,
                delta: WireTextDelta,
            }
            ClaudeManagedInbound::AppendText(strict::<Frame>(value)?.delta)
        }
        "turn" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Frame {
                #[allow(dead_code)]
                v: u8,
                #[serde(rename = "type")]
                #[allow(dead_code)]
                message_type: String,
                state: String,
                #[serde(default)]
                run_id: Option<String>,
                #[serde(default)]
                activity: Option<String>,
            }
            let frame: Frame = strict(value)?;
            ClaudeManagedInbound::Turn {
                state: frame.state,
                run_id: frame.run_id,
                activity: frame.activity,
            }
        }
        "command_capabilities" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Frame {
                #[allow(dead_code)]
                v: u8,
                #[serde(rename = "type")]
                #[allow(dead_code)]
                message_type: String,
                prompt: bool,
                interrupt: bool,
                #[serde(default)]
                permission_mode: bool,
                #[serde(default)]
                model: bool,
                #[serde(default)]
                effort: bool,
            }
            let frame: Frame = strict(value)?;
            ClaudeManagedInbound::CommandCapabilities {
                prompt: frame.prompt,
                interrupt: frame.interrupt,
                permission_mode: frame.permission_mode,
                model: frame.model,
                effort: frame.effort,
            }
        }
        "command_receipt" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Frame {
                #[allow(dead_code)]
                v: u8,
                #[serde(rename = "type")]
                #[allow(dead_code)]
                message_type: String,
                command_id: String,
                state: String,
                #[serde(default)]
                evidence: Option<String>,
                #[serde(default)]
                reason_code: Option<String>,
            }
            let frame: Frame = strict(value)?;
            ClaudeManagedInbound::CommandReceipt {
                command_id: frame.command_id,
                state: frame.state,
                evidence: frame.evidence,
                reason_code: frame.reason_code,
            }
        }
        "vendor_session" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Frame {
                #[allow(dead_code)]
                v: u8,
                #[serde(rename = "type")]
                #[allow(dead_code)]
                message_type: String,
                vendor_session_id: String,
            }
            ClaudeManagedInbound::VendorSession(strict::<Frame>(value)?.vendor_session_id)
        }
        "permission_mode" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Frame {
                #[allow(dead_code)]
                v: u8,
                #[serde(rename = "type")]
                #[allow(dead_code)]
                message_type: String,
                mode: String,
            }
            ClaudeManagedInbound::PermissionMode(strict::<Frame>(value)?.mode)
        }
        "model" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Frame {
                #[allow(dead_code)]
                v: u8,
                #[serde(rename = "type")]
                #[allow(dead_code)]
                message_type: String,
                model: String,
            }
            ClaudeManagedInbound::Model(strict::<Frame>(value)?.model)
        }
        "effort" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Frame {
                #[allow(dead_code)]
                v: u8,
                #[serde(rename = "type")]
                #[allow(dead_code)]
                message_type: String,
                effort: String,
            }
            ClaudeManagedInbound::Effort(strict::<Frame>(value)?.effort)
        }
        "model_catalogue" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Frame {
                #[allow(dead_code)]
                v: u8,
                #[serde(rename = "type")]
                #[allow(dead_code)]
                message_type: String,
                models: Vec<AgentModelOption>,
            }
            ClaudeManagedInbound::ModelCatalogue(strict::<Frame>(value)?.models)
        }
        "upsert_interaction" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Frame {
                #[allow(dead_code)]
                v: u8,
                #[serde(rename = "type")]
                #[allow(dead_code)]
                message_type: String,
                interaction: ClaudeManagedInteraction,
            }
            ClaudeManagedInbound::UpsertInteraction(strict::<Frame>(value)?.interaction)
        }
        "resolve_interaction" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Frame {
                #[allow(dead_code)]
                v: u8,
                #[serde(rename = "type")]
                #[allow(dead_code)]
                message_type: String,
                interaction_id: String,
                resolution: String,
            }
            let frame: Frame = strict(value)?;
            ClaudeManagedInbound::ResolveInteraction {
                interaction_id: frame.interaction_id,
                resolution: frame.resolution,
            }
        }
        "notification" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Frame {
                #[allow(dead_code)]
                v: u8,
                #[serde(rename = "type")]
                #[allow(dead_code)]
                message_type: String,
                kind: String,
            }
            ClaudeManagedInbound::Notification(strict::<Frame>(value)?.kind)
        }
        "drift_note" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Frame {
                #[allow(dead_code)]
                v: u8,
                #[serde(rename = "type")]
                #[allow(dead_code)]
                message_type: String,
                surface: String,
                name: String,
            }
            let frame = strict::<Frame>(value)?;
            // The worker bounds these; a lying worker is bounded again here before anything
            // reaches the ledger.
            if frame.surface.len() > 48 || frame.name.len() > 48 {
                return Err(AgentProtocolError::MalformedJson);
            }
            ClaudeManagedInbound::DriftNote {
                surface: frame.surface,
                name: frame.name,
            }
        }
        _ => ClaudeManagedInbound::Unknown,
    })
}

impl AttachedAgentAdapter for ClaudeManagedAdapter {
    fn id(&self) -> &'static str {
        "claude-managed"
    }

    fn decode_registration(
        &self,
        body: &[u8],
        peer_process_id: Option<u32>,
    ) -> Result<NormalizedRegistration, AgentProtocolError> {
        match decode_managed_frame(body)? {
            ClaudeManagedInbound::Register(registration) => registration.normalize(peer_process_id),
            _ => Err(AgentProtocolError::UnexpectedMessage),
        }
    }

    fn decode_event(&self, body: &[u8]) -> Result<NormalizedAdapterEvent, AgentProtocolError> {
        Ok(match decode_managed_frame(body)? {
            ClaudeManagedInbound::Register(_) => NormalizedAdapterEvent::Registration,
            ClaudeManagedInbound::Heartbeat => NormalizedAdapterEvent::Heartbeat,
            ClaudeManagedInbound::DriftNote { surface, name } => {
                // Tallied here and surfaced as a heartbeat: the note is true whenever the
                // worker is alive to send it, and no timeline entry should exist for it.
                crate::drift::note("claude-managed", &surface, "unknown_event", &name, None);
                NormalizedAdapterEvent::Heartbeat
            }
            ClaudeManagedInbound::SnapshotStart => NormalizedAdapterEvent::SnapshotStart,
            ClaudeManagedInbound::SnapshotEntry(entry) => {
                NormalizedAdapterEvent::SnapshotEntry(entry.normalize()?)
            }
            ClaudeManagedInbound::SnapshotEnd => NormalizedAdapterEvent::SnapshotEnd,
            ClaudeManagedInbound::UpsertEntry(entry) => {
                NormalizedAdapterEvent::UpsertEntry(entry.normalize()?)
            }
            ClaudeManagedInbound::AppendText(delta) => {
                NormalizedAdapterEvent::AppendText(delta.normalize()?)
            }
            ClaudeManagedInbound::CommandCapabilities {
                prompt,
                interrupt,
                permission_mode,
                model,
                effort,
            } => NormalizedAdapterEvent::CommandCapabilities(CommandCapabilities {
                prompt,
                steer: false,
                follow_up: false,
                interrupt,
                permission_mode,
                model,
                effort,
            }),
            ClaudeManagedInbound::PermissionMode(mode) => {
                if !crate::agent_protocol::valid_permission_mode(&mode) {
                    return Err(AgentProtocolError::InvalidValue);
                }
                NormalizedAdapterEvent::PermissionMode(mode)
            }
            ClaudeManagedInbound::Model(model) => {
                valid_model_id(&model)?;
                NormalizedAdapterEvent::Model(model)
            }
            // Union-checked, not merely tokenised: the levels are the pin's own fixed set, so a
            // worker reporting one outside it is reporting something this pin cannot produce.
            ClaudeManagedInbound::Effort(effort) => {
                if !PINNED_EFFORT_LEVELS.contains(&effort.as_str()) {
                    return Err(AgentProtocolError::InvalidValue);
                }
                NormalizedAdapterEvent::Effort(effort)
            }
            ClaudeManagedInbound::ModelCatalogue(models) => {
                validate_model_catalogue(&models)?;
                NormalizedAdapterEvent::ModelCatalogue(models)
            }
            ClaudeManagedInbound::CommandReceipt {
                command_id,
                state,
                evidence,
                reason_code,
            } => {
                valid_opaque_id(&command_id)?;
                valid_token(&state)?;
                NormalizedAdapterEvent::CommandReceipt {
                    command_id,
                    state,
                    evidence,
                    reason_code,
                }
            }
            ClaudeManagedInbound::Turn {
                state,
                run_id,
                activity,
            } => NormalizedAdapterEvent::Turn(turn_from_bridge_frame(&state, run_id, activity)?),
            ClaudeManagedInbound::VendorSession(vendor_session_id) => {
                // The vendor ID is opaque to Ciao but must stay bounded and
                // safe as a lookup key.
                valid_opaque_id(&vendor_session_id)?;
                NormalizedAdapterEvent::VendorSession(vendor_session_id)
            }
            ClaudeManagedInbound::UpsertInteraction(interaction) => {
                NormalizedAdapterEvent::UpsertInteraction(Box::new(interaction.normalize()?))
            }
            ClaudeManagedInbound::ResolveInteraction {
                interaction_id,
                resolution,
            } => {
                valid_opaque_id(&interaction_id)?;
                valid_token(&resolution)?;
                NormalizedAdapterEvent::ResolveInteraction {
                    interaction_id,
                    resolution,
                }
            }
            ClaudeManagedInbound::Notification(kind) => {
                valid_token(&kind)?;
                NormalizedAdapterEvent::Notification(kind)
            }
            ClaudeManagedInbound::SessionEnd => NormalizedAdapterEvent::SessionEnded,
            ClaudeManagedInbound::Unknown => NormalizedAdapterEvent::Unknown,
        })
    }

    fn registered_frame(
        &self,
        session: &RegisteredAgentSession,
    ) -> Result<Value, AgentProtocolError> {
        serde_json::to_value(ClaudeManagedOutbound::Registered {
            v: CLAUDE_MANAGED_PROTOCOL_VERSION,
            session_id: session.session_id.clone(),
            process_generation: session.process_generation,
            snapshot_epoch: session.snapshot_epoch,
        })
        .map_err(|_| AgentProtocolError::MalformedJson)
    }

    /// The outbound vocabulary is fixed to the advertised operations. There is
    /// no generic invocation, slash command, or arbitrary SDK call.
    fn command_frame(&self, command: AgentCommand) -> Result<Value, AgentProtocolError> {
        let outbound = match command.kind {
            AgentCommandKind::Prompt { text } => ClaudeManagedOutbound::Command {
                v: CLAUDE_MANAGED_PROTOCOL_VERSION,
                command_id: command.command_id,
                kind: "prompt".into(),
                text: Some(text),
                interaction_id: None,
                choice_id: None,
                answers: None,
                mode: None,
                model: None,
                effort: None,
            },
            AgentCommandKind::Interrupt => ClaudeManagedOutbound::Command {
                v: CLAUDE_MANAGED_PROTOCOL_VERSION,
                command_id: command.command_id,
                kind: "interrupt".into(),
                text: None,
                interaction_id: None,
                choice_id: None,
                answers: None,
                mode: None,
                model: None,
                effort: None,
            },
            AgentCommandKind::InteractionResponse {
                interaction_id,
                interaction_revision: _,
                answer,
            } => {
                let (choice_id, answers) = match answer {
                    // A permission response carries exactly one host-issued choice.
                    crate::agent_protocol::InteractionAnswer::Choices { choice_ids } => {
                        let [choice_id] = choice_ids.as_slice() else {
                            return Err(AgentProtocolError::InvalidValue);
                        };
                        (Some(choice_id.clone()), None)
                    }
                    // A question response carries one answer per question. The worker holds the
                    // tool's own labels, so the wire stays identifiers and free text.
                    crate::agent_protocol::InteractionAnswer::Questions { answers } => {
                        (None, Some(answers))
                    }
                    _ => return Err(AgentProtocolError::InvalidValue),
                };
                ClaudeManagedOutbound::Command {
                    v: CLAUDE_MANAGED_PROTOCOL_VERSION,
                    command_id: command.command_id,
                    kind: "interaction_response".into(),
                    text: None,
                    interaction_id: Some(interaction_id),
                    choice_id,
                    answers,
                    mode: None,
                    model: None,
                    effort: None,
                }
            }
            AgentCommandKind::SetPermissionMode { mode } => ClaudeManagedOutbound::Command {
                v: CLAUDE_MANAGED_PROTOCOL_VERSION,
                command_id: command.command_id,
                kind: "set_permission_mode".into(),
                text: None,
                interaction_id: None,
                choice_id: None,
                answers: None,
                mode: Some(mode),
                model: None,
                effort: None,
            },
            // The model id is carried as the vendor's own string. It is checked for grammar and
            // bounds upstream, and against the catalogue the SDK actually published by the
            // worker; there is deliberately no list of model names compiled in here, because
            // this file would then have to ship every time Anthropic named a model.
            AgentCommandKind::SetModel { model } => ClaudeManagedOutbound::Command {
                v: CLAUDE_MANAGED_PROTOCOL_VERSION,
                command_id: command.command_id,
                kind: "set_model".into(),
                text: None,
                interaction_id: None,
                choice_id: None,
                answers: None,
                mode: None,
                model: Some(model),
                effort: None,
            },
            // Effort *is* union-checked here, unlike the model: the levels are the pinned SDK's
            // own fixed set, not a catalogue that grows between releases, so an unknown one is
            // a bug rather than a new offering and is refused before it reaches the worker.
            AgentCommandKind::SetEffort { effort } => {
                if !PINNED_EFFORT_LEVELS.contains(&effort.as_str()) {
                    return Err(AgentProtocolError::InvalidValue);
                }
                ClaudeManagedOutbound::Command {
                    v: CLAUDE_MANAGED_PROTOCOL_VERSION,
                    command_id: command.command_id,
                    kind: "set_effort".into(),
                    text: None,
                    interaction_id: None,
                    choice_id: None,
                    answers: None,
                    mode: None,
                    model: None,
                    effort: Some(effort),
                }
            }
            AgentCommandKind::Steer { .. }
            | AgentCommandKind::FollowUp { .. }
            | AgentCommandKind::Unknown => return Err(AgentProtocolError::UnexpectedMessage),
        };
        serde_json::to_value(outbound).map_err(|_| AgentProtocolError::MalformedJson)
    }

    fn shutdown_frame(&self, reason_code: &str) -> Result<Value, AgentProtocolError> {
        valid_token(reason_code)?;
        serde_json::to_value(ClaudeManagedOutbound::Shutdown {
            v: CLAUDE_MANAGED_PROTOCOL_VERSION,
            reason_code: reason_code.to_owned(),
        })
        .map_err(|_| AgentProtocolError::MalformedJson)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::agent_protocol::{InteractionAnswer, ResponseChoice};

    fn register_frame(version: &str, sdk: &str) -> Vec<u8> {
        // The shape the current worker emits for a fresh session: it has no earlier transcript,
        // so its snapshot plus live stream is complete.
        register_frame_resuming(version, sdk, Some(false), Some(true))
    }

    fn register_frame_resuming(
        version: &str,
        sdk: &str,
        resumed: Option<bool>,
        history_complete: Option<bool>,
    ) -> Vec<u8> {
        let mut frame = json!({
            "v": 1,
            "type": "register",
            "adapter": "claude-managed",
            "adapter_version": version,
            "sdk_version": sdk,
            "spawn_token": "0123456789abcdef0123456789abcdef",
            "session_id": "managed-session",
            "process_nonce": "fedcba9876543210fedcba9876543210",
            "process_id": 4242,
            "workspace_display": "Fixture workspace",
        });
        if let Some(resumed) = resumed {
            frame["resumed"] = json!(resumed);
        }
        if let Some(history_complete) = history_complete {
            frame["history_complete"] = json!(history_complete);
        }
        serde_json::to_vec(&frame).unwrap()
    }

    /// A resumed session marks only history it could not load. The current worker snapshots a
    /// complete bounded transcript before it accepts a prompt; the marker remains the honest
    /// fallback for an unreadable/over-bound transcript and for the older marker-only worker.
    #[test]
    fn a_resumed_worker_marks_only_history_it_could_not_load() {
        let adapter = ClaudeManagedAdapter;
        let facts = |resumed: Option<bool>, history_complete: Option<bool>| {
            let registration = adapter
                .decode_registration(
                    &register_frame_resuming(
                        PINNED_MANAGED_CLI_VERSION,
                        PINNED_CLAUDE_SDK_VERSION,
                        resumed,
                        history_complete,
                    ),
                    Some(1),
                )
                .unwrap();
            (
                registration.history_boundary,
                registration.capabilities.history,
            )
        };
        assert_eq!(facts(Some(true), Some(true)), (None, "full".into()));
        assert_eq!(
            facts(Some(true), Some(false)),
            (Some("resume".into()), "live_tail".into())
        );
        assert_eq!(
            facts(Some(true), None),
            (Some("resume".into()), "live_tail".into()),
            "the marker-only worker remains honest"
        );
        assert_eq!(
            facts(Some(false), Some(true)),
            (None, "full".into()),
            "a fresh session has no boundary"
        );
        assert_eq!(
            facts(None, None),
            (None, "live_tail".into()),
            "a worker older than the resumed field reads as fresh"
        );
    }

    #[test]
    fn managed_registration_is_headless_and_pin_gated() {
        let adapter = ClaudeManagedAdapter;
        let registration = adapter
            .decode_registration(
                &register_frame(PINNED_MANAGED_CLI_VERSION, PINNED_CLAUDE_SDK_VERSION),
                Some(1),
            )
            .unwrap();
        registration.validate().unwrap();
        assert_eq!(registration.topology, "managed");
        assert_eq!(registration.control_owner, "none");
        assert_eq!(registration.capabilities.terminal_continuity, "unavailable");
        assert_eq!(registration.capabilities.history, "full");
        assert!(registration.capabilities.commands.prompt);
        assert!(registration.capabilities.commands.interrupt);
        // Provenance, not coverage, is what now licenses the phone to say "working": a `running`
        // turn must only ever come from a turn frame the adapter sent. Registration starts
        // elsewhere, here and in every other adapter.
        assert!(!registration.turn.is_authoritative_working());
        // Permission and question are advertised so a raised card can actually be answered; plan
        // and review decisions remain disabled at this stage. The question bounds are the pinned
        // SDK's `AskUserQuestionInput`, and free text is the tool's automatic "Other".
        assert!(registration.capabilities.interactions.permission.enabled);
        let question = &registration.capabilities.interactions.question;
        assert!(question.enabled);
        assert_eq!(question.max_questions, 4);
        assert_eq!(question.max_options_per_question, 4);
        assert!(question.allows_free_text);
        assert!(!registration.capabilities.interactions.plan_decision.enabled);
        assert!(
            registration
                .capabilities
                .permits(&AgentCommandKind::InteractionResponse {
                    interaction_id: "interaction-a".into(),
                    interaction_revision: 1,
                    answer: InteractionAnswer::Choices {
                        choice_ids: vec!["deny".into()]
                    },
                })
        );
        // Steer and follow-up are never advertised at this capability stage.
        assert!(!registration.capabilities.commands.steer);
        assert!(!registration.capabilities.commands.follow_up);

        // Either half of the pin being wrong downgrades categorically.
        for (cli, sdk) in [
            ("2.1.219", PINNED_CLAUDE_SDK_VERSION),
            (PINNED_MANAGED_CLI_VERSION, "0.3.219"),
        ] {
            let downgraded = adapter
                .decode_registration(&register_frame(cli, sdk), Some(1))
                .unwrap();
            downgraded.validate().unwrap();
            assert!(!downgraded.compatible);
            assert_eq!(
                downgraded.capabilities.commands,
                CommandCapabilities::none()
            );
            assert_eq!(downgraded.capabilities.history, "live_tail");
            assert_eq!(downgraded.observation.coverage, "unavailable");
        }

        // A peerless or malformed registration fails closed.
        assert!(
            adapter
                .decode_registration(
                    &register_frame(PINNED_MANAGED_CLI_VERSION, PINNED_CLAUDE_SDK_VERSION),
                    None
                )
                .is_err()
        );
    }

    #[test]
    fn permission_interactions_map_and_unsupported_kinds_fail_closed() {
        let adapter = ClaudeManagedAdapter;
        let frame = serde_json::to_vec(&json!({
            "v": 1,
            "type": "upsert_interaction",
            "interaction": {
                "interaction_id": "interaction-a",
                "interaction_revision": 1,
                "kind": "permission",
                "created_at": 1_700_000_000_u64,
                "title": "Synthetic permission",
                "body": "Synthetic bounded body.",
                "response_schema": {
                    "type": "choices",
                    "minimum": 1,
                    "maximum": 1,
                    "choices": [
                        { "choice_id": "allow-once", "label": "Allow once", "scope": "once" },
                        { "choice_id": "deny", "label": "Deny", "scope": "request" },
                    ],
                },
            },
        }))
        .unwrap();
        let NormalizedAdapterEvent::UpsertInteraction(interaction) =
            adapter.decode_event(&frame).unwrap()
        else {
            panic!("expected a pending interaction");
        };
        assert!(interaction.blocking);
        assert_eq!(interaction.state, "pending");
        assert_eq!(interaction.terminal_fallback.continuity, "unavailable");
        assert!(interaction.terminal_fallback.route_id.is_none());

        // A question carries its own schema through, headers and descriptions included: they are
        // the two fields that make an option decidable, and dropping either would leave the phone
        // rendering nouns with no consequence attached.
        let question = serde_json::to_vec(&json!({
            "v": 1,
            "type": "upsert_interaction",
            "interaction": {
                "interaction_id": "interaction-b",
                "interaction_revision": 1,
                "kind": "question",
                "created_at": 1_700_000_000_u64,
                "title": "Claude has a question",
                "body": "",
                "response_schema": {
                    "type": "questions",
                    "questions": [{
                        "question_id": "q0",
                        "prompt": "Which transport should it use?",
                        "response_kind": "single_choice",
                        "required": true,
                        "header": "Transport",
                        "options": [
                            {
                                "choice_id": "q0-o0",
                                "label": "Iroh",
                                "description": "Direct QUIC where possible.",
                            },
                            {
                                "choice_id": "q0-o1",
                                "label": "Relay only",
                                "description": "Always through the relay.",
                            },
                        ],
                        "max_text_bytes": 4096,
                    }],
                },
            },
        }))
        .unwrap();
        let NormalizedAdapterEvent::UpsertInteraction(interaction) =
            adapter.decode_event(&question).unwrap()
        else {
            panic!("expected a pending question");
        };
        assert_eq!(interaction.kind, "question");
        let ResponseSchema::Questions { questions } = &interaction.response_schema else {
            panic!("expected a questions schema");
        };
        assert_eq!(questions[0].header.as_deref(), Some("Transport"));
        assert_eq!(
            questions[0].options[0].description.as_deref(),
            Some("Direct QUIC where possible.")
        );

        // A plan decision still is not permitted at this capability stage.
        let plan = serde_json::to_vec(&json!({
            "v": 1,
            "type": "upsert_interaction",
            "interaction": {
                "interaction_id": "interaction-c",
                "interaction_revision": 1,
                "kind": "plan_decision",
                "created_at": 1_700_000_000_u64,
                "body": "Synthetic plan.",
                "response_schema": { "type": "free_text", "maximum_bytes": 1024 },
            },
        }))
        .unwrap();
        assert!(adapter.decode_event(&plan).is_err());

        // Unknown frames stay categorical; a wrong version fails closed.
        assert_eq!(
            adapter
                .decode_event(&serde_json::to_vec(&json!({"v": 1, "type": "future"})).unwrap())
                .unwrap(),
            NormalizedAdapterEvent::Unknown
        );
        assert!(
            adapter
                .decode_event(&serde_json::to_vec(&json!({"v": 2, "type": "heartbeat"})).unwrap())
                .is_err()
        );
    }

    /// The worker's drift report: tallied into the ledger, surfaced as nothing more than a
    /// heartbeat, and held to the same strictness as every other managed frame.
    #[test]
    fn a_drift_note_tallies_and_is_only_a_heartbeat() {
        let adapter = ClaudeManagedAdapter;
        let note = serde_json::to_vec(&json!({
            "v": 1,
            "type": "drift_note",
            "surface": "sdk_stream",
            "name": "ManagedTestFutureMessage",
        }))
        .unwrap();
        assert_eq!(
            adapter.decode_event(&note).unwrap(),
            NormalizedAdapterEvent::Heartbeat
        );
        let ledger = crate::drift::snapshot();
        let managed = &ledger.vendors["claude-managed"];
        let tallied = managed
            .signatures
            .iter()
            .find(|signature| signature.name == "ManagedTestFutureMessage")
            .expect("the worker's name reaches the ledger");
        assert_eq!(tallied.surface, "sdk_stream");
        assert_eq!(tallied.kind, "unknown_event");

        let stray_field = serde_json::to_vec(&json!({
            "v": 1,
            "type": "drift_note",
            "surface": "sdk_stream",
            "name": "x",
            "payload": "never",
        }))
        .unwrap();
        assert!(adapter.decode_event(&stray_field).is_err());

        let oversized = serde_json::to_vec(&json!({
            "v": 1,
            "type": "drift_note",
            "surface": "sdk_stream",
            "name": "x".repeat(200),
        }))
        .unwrap();
        assert!(adapter.decode_event(&oversized).is_err());
    }

    /// The worker owns both turn edges. Anything it cannot prove — a state Ciao never taught it,
    /// a running turn with no run to point at — is rejected rather than shown as activity.
    #[test]
    fn turn_edges_decode_and_anything_unproven_is_refused() {
        let adapter = ClaudeManagedAdapter;
        let decode = |value| adapter.decode_event(&serde_json::to_vec(&value).unwrap());

        assert_eq!(
            decode(json!({
                "v": 1, "type": "turn", "state": "running",
                "run_id": "run-1", "activity": "thinking",
            }))
            .unwrap(),
            NormalizedAdapterEvent::Turn(TurnState::Running {
                run_id: "run-1".into(),
                activity: "thinking".into(),
            })
        );
        assert_eq!(
            decode(json!({ "v": 1, "type": "turn", "state": "completed", "run_id": "run-1" }))
                .unwrap(),
            NormalizedAdapterEvent::Turn(TurnState::Completed {
                run_id: Some("run-1".into()),
            })
        );
        // A turn can end without a run to name, which is what a resume or an interrupt looks like.
        assert_eq!(
            decode(json!({ "v": 1, "type": "turn", "state": "completed" })).unwrap(),
            NormalizedAdapterEvent::Turn(TurnState::Completed { run_id: None })
        );

        assert!(decode(json!({ "v": 1, "type": "turn", "state": "running" })).is_err());
        assert!(
            decode(json!({
                "v": 1, "type": "turn", "state": "running", "run_id": "run-1",
            }))
            .is_err()
        );
        assert!(decode(json!({ "v": 1, "type": "turn", "state": "pondering" })).is_err());
        assert!(
            decode(json!({
                "v": 1, "type": "turn", "state": "running",
                "run_id": "run 1", "activity": "thinking",
            }))
            .is_err()
        );
    }

    /// A worker written before model and effort existed must read as not offering them, rather
    /// than failing to decode — the same degradation `permission_mode` already relies on.
    #[test]
    fn an_older_workers_capability_frame_reads_as_not_offering_model_or_effort() {
        let adapter = ClaudeManagedAdapter;
        let legacy = serde_json::to_vec(&serde_json::json!({
            "v": 1, "type": "command_capabilities", "prompt": true, "interrupt": true
        }))
        .unwrap();
        let NormalizedAdapterEvent::CommandCapabilities(commands) =
            adapter.decode_event(&legacy).unwrap()
        else {
            panic!("a capability frame decodes to capabilities");
        };
        assert!(commands.prompt);
        assert!(!commands.permission_mode);
        assert!(
            !commands.model,
            "an absent capability is not an offered one"
        );
        assert!(!commands.effort);

        let offered = serde_json::to_vec(&serde_json::json!({
            "v": 1, "type": "command_capabilities",
            "prompt": true, "interrupt": true, "permission_mode": true,
            "model": true, "effort": true
        }))
        .unwrap();
        let NormalizedAdapterEvent::CommandCapabilities(commands) =
            adapter.decode_event(&offered).unwrap()
        else {
            panic!("a capability frame decodes to capabilities");
        };
        assert!(commands.model && commands.effort);
    }

    /// The catalogue is the vendor's list, so the host checks only what it can honestly own:
    /// that every row is well-formed and the whole thing fits what a frame will carry.
    #[test]
    fn a_published_catalogue_is_bounded_and_its_effort_levels_are_the_pins_own() {
        let adapter = ClaudeManagedAdapter;
        let catalogue = |models: serde_json::Value| {
            serde_json::to_vec(&serde_json::json!({
                "v": 1, "type": "model_catalogue", "models": models
            }))
            .unwrap()
        };
        let good = catalogue(serde_json::json!([{
            "value": "claude-opus-5[1m]",
            "display_name": "Opus 5 (1M)",
            "supports_effort": true,
            "supported_effort_levels": ["low", "medium", "high", "xhigh", "max"]
        }]));
        let NormalizedAdapterEvent::ModelCatalogue(models) = adapter.decode_event(&good).unwrap()
        else {
            panic!("a catalogue frame decodes to a catalogue");
        };
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].value, "claude-opus-5[1m]");
        assert_eq!(models[0].supported_effort_levels.len(), 5);

        // Hostile shapes are refused whole rather than partially accepted: a menu is only ever
        // right as a set.
        let over_long_list = serde_json::Value::Array(
            (0..(crate::agent_protocol::MAX_MODEL_CATALOGUE_ENTRIES + 1))
                .map(|index| {
                    serde_json::json!({ "value": format!("model-{index}"), "display_name": "M" })
                })
                .collect(),
        );
        for hostile in [
            over_long_list,
            // An id past the bound.
            serde_json::json!([{ "value": "x".repeat(65), "display_name": "M" }]),
            // A display name past the bound.
            serde_json::json!([{ "value": "m", "display_name": "N".repeat(49) }]),
            // A grammar the id may not use.
            serde_json::json!([{ "value": "model/../etc", "display_name": "M" }]),
            // An empty display name says nothing a picker could render.
            serde_json::json!([{ "value": "m", "display_name": "" }]),
            // Vendor prose is not a field this wire carries.
            serde_json::json!([{ "value": "m", "display_name": "M", "description": "prose" }]),
        ] {
            assert!(
                adapter.decode_event(&catalogue(hostile.clone())).is_err(),
                "{hostile} must be refused"
            );
        }

        // A level outside the pin is refused on the way in, too.
        let bad_effort = serde_json::to_vec(
            &serde_json::json!({ "v": 1, "type": "effort", "effort": "ludicrous" }),
        )
        .unwrap();
        assert!(adapter.decode_event(&bad_effort).is_err());
        let bad_model =
            serde_json::to_vec(&serde_json::json!({ "v": 1, "type": "model", "model": "a/b" }))
                .unwrap();
        assert!(adapter.decode_event(&bad_model).is_err());
    }

    #[test]
    fn outbound_commands_are_a_fixed_vocabulary() {
        let adapter = ClaudeManagedAdapter;
        let command = |kind| AgentCommand {
            v: 1,
            command_id: "command-a".into(),
            session_id: "managed-session".into(),
            snapshot_epoch: 1,
            expected_generation: 1,
            expected_revision: None,
            kind,
        };
        let prompt = adapter
            .command_frame(command(AgentCommandKind::Prompt {
                text: "Synthetic prompt.".into(),
            }))
            .unwrap();
        assert_eq!(prompt["kind"], "prompt");
        assert_eq!(prompt["text"], "Synthetic prompt.");
        let interrupt = adapter
            .command_frame(command(AgentCommandKind::Interrupt))
            .unwrap();
        assert_eq!(interrupt["kind"], "interrupt");
        assert!(interrupt.get("text").is_none());

        let response = adapter
            .command_frame(command(AgentCommandKind::InteractionResponse {
                interaction_id: "interaction-a".into(),
                interaction_revision: 1,
                answer: InteractionAnswer::Choices {
                    choice_ids: vec!["allow-once".into()],
                },
            }))
            .unwrap();
        assert_eq!(response["kind"], "interaction_response");
        assert_eq!(response["choice_id"], "allow-once");
        assert!(response.get("answers").is_none());

        // A question answer travels as identifiers plus free text. The worker holds the tool's
        // own labels, so nothing the agent wrote has to come back down the wire to be sent up it.
        let answered = adapter
            .command_frame(command(AgentCommandKind::InteractionResponse {
                interaction_id: "interaction-b".into(),
                interaction_revision: 1,
                answer: InteractionAnswer::Questions {
                    answers: vec![
                        crate::agent_protocol::QuestionAnswer {
                            question_id: "q0".into(),
                            choice_ids: vec!["q0-o1".into()],
                            text: None,
                        },
                        crate::agent_protocol::QuestionAnswer {
                            question_id: "q1".into(),
                            choice_ids: vec![],
                            text: Some("Something else entirely".into()),
                        },
                    ],
                },
            }))
            .unwrap();
        assert_eq!(answered["kind"], "interaction_response");
        assert!(answered.get("choice_id").is_none());
        assert_eq!(answered["answers"][0]["choice_ids"][0], "q0-o1");
        assert_eq!(answered["answers"][1]["text"], "Something else entirely");

        // Multi-choice, free text, steer, and follow-up have no managed mapping.
        for unmapped in [
            AgentCommandKind::InteractionResponse {
                interaction_id: "interaction-a".into(),
                interaction_revision: 1,
                answer: InteractionAnswer::Choices {
                    choice_ids: vec!["allow-once".into(), "deny".into()],
                },
            },
            AgentCommandKind::InteractionResponse {
                interaction_id: "interaction-a".into(),
                interaction_revision: 1,
                answer: InteractionAnswer::FreeText {
                    text: "synthetic".into(),
                },
            },
            AgentCommandKind::Steer {
                text: "synthetic".into(),
            },
            AgentCommandKind::FollowUp {
                text: "synthetic".into(),
            },
        ] {
            assert!(adapter.command_frame(command(unmapped)).is_err());
        }

        // The model rides as the vendor's own string, brackets and all, with no list of names
        // compiled into this file to go stale.
        let model = adapter
            .command_frame(command(AgentCommandKind::SetModel {
                model: "claude-opus-5[1m]".into(),
            }))
            .unwrap();
        assert_eq!(model["kind"], "set_model");
        assert_eq!(model["model"], "claude-opus-5[1m]");
        assert!(model.get("mode").is_none());
        assert!(model.get("effort").is_none());

        let effort = adapter
            .command_frame(command(AgentCommandKind::SetEffort {
                effort: "xhigh".into(),
            }))
            .unwrap();
        assert_eq!(effort["kind"], "set_effort");
        assert_eq!(effort["effort"], "xhigh");
        assert!(effort.get("model").is_none());

        // Effort *is* union-checked here, unlike the model: the levels are the pin's own fixed
        // set, so one outside it is a bug rather than a new offering and never reaches a worker.
        for level in ["ludicrous", "LOW", "medium ", ""] {
            assert!(
                adapter
                    .command_frame(command(AgentCommandKind::SetEffort {
                        effort: level.into(),
                    }))
                    .is_err(),
                "{level} is not a level this pin can run"
            );
        }

        let _ = ResponseChoice {
            choice_id: "allow-once".into(),
            label: "Allow once".into(),
            description: None,
            scope: Some("once".into()),
        };
    }
}
