//! Pi 0.81.1 attached-TUI bridge adapter (Spec 005 §9).
//!
//! Pi-owned shapes stop here. The supervisor receives only Ciao canonical registrations, entries,
//! command capabilities, and categorical receipts. There is no arbitrary invocation, argv, file,
//! environment, credential, or terminal-byte field in this protocol.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    agent_adapter::{
        AttachedAgentAdapter, NormalizedAdapterEvent, WireTimelineEntry, decode_unit_frame,
        validate_frame_header,
    },
    agent_protocol::{
        AgentCapabilities, AgentCommand, AgentCommandKind, AgentProtocolError, CommandCapabilities,
        InteractionCapabilities, Observation, TurnState, decode_agent_body, turn_from_bridge_frame,
        valid_opaque_id, valid_token, version_major_matches, version_within_tested_minor,
    },
    agent_session::{NormalizedRegistration, RegisteredAgentSession},
};

pub(crate) const PINNED_PI_VERSION: &str = "0.81.1";
pub(crate) const PI_BRIDGE_PROTOCOL_VERSION: u8 = 1;

pub(crate) struct PiAttachedAdapter;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PiBridgeCommandCapabilities {
    pub prompt: bool,
    pub steer: bool,
    pub follow_up: bool,
    pub interrupt: bool,
}

impl From<PiBridgeCommandCapabilities> for CommandCapabilities {
    fn from(value: PiBridgeCommandCapabilities) -> Self {
        Self {
            prompt: value.prompt,
            steer: value.steer,
            follow_up: value.follow_up,
            interrupt: value.interrupt,
            // Pi's bridge has no permission-mode control, so it never advertises one and the
            // command below is refused rather than translated into something approximate.
            permission_mode: false,
            // GAP(parity): deliberate, and enforced from the other direction. `setModel(` is on
            // the embedded extension's forbidden list — see `pi_integration`'s
            // `embedded_extension_has_a_small_fixed_command_and_no_ui_interception_surface` —
            // because that extension is kept to a small fixed command surface with no UI
            // interception. Advertising a model switch here would mean widening that surface,
            // which is a decision about Pi's extension, not about this picker.
            model: false,
            effort: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PiBridgeRegister {
    pub v: u8,
    #[serde(rename = "type")]
    pub message_type: String,
    #[serde(default)]
    pub adapter: Option<String>,
    pub adapter_version: String,
    pub mode: String,
    pub session_id: String,
    pub process_nonce: String,
    pub process_id: u32,
    pub workspace_display: String,
    pub commands: PiBridgeCommandCapabilities,
}

impl PiBridgeRegister {
    pub(crate) fn normalize(
        self,
        peer_process_id: Option<u32>,
    ) -> Result<NormalizedRegistration, AgentProtocolError> {
        if self.v != PI_BRIDGE_PROTOCOL_VERSION
            || self.message_type != "register"
            || self
                .adapter
                .as_deref()
                .is_some_and(|adapter| adapter != "pi")
            || self.mode != "tui"
            || self.process_id == 0
            || peer_process_id.is_some_and(|pid| pid != self.process_id)
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        valid_opaque_id(&self.session_id)?;
        valid_opaque_id(&self.process_nonce)?;
        valid_token(&self.adapter_version)?;
        if self.workspace_display.is_empty() || self.workspace_display.len() > 256 {
            return Err(AgentProtocolError::InvalidValue);
        }
        // The bridge is Ciao's own code running inside Pi, and it advertises a command only
        // after finding the surface that performs it. That is a better answer than a version
        // string, so the host stops second-guessing it and refuses only what the vendor has
        // declared incompatible. `tested` still distinguishes a build conformance actually
        // covered, which the reason code reports rather than silently implying.
        let tested = version_within_tested_minor(&self.adapter_version, PINNED_PI_VERSION);
        let compatible = version_major_matches(&self.adapter_version, PINNED_PI_VERSION);
        Ok(NormalizedRegistration {
            history_boundary: None,
            upstream_identity: self.session_id,
            process_nonce: self.process_nonce,
            process_id: self.process_id,
            adapter_family: "Pi".into(),
            adapter_version: self.adapter_version,
            topology: "attached".into(),
            compatible,
            // Pi named these states before Spec 017 did: a compatible-but-untested build is
            // exactly `ahead`, with the bridge's surface detection as its standing evidence.
            version_state: match (compatible, tested) {
                (true, true) => "grounded",
                (true, false) => "ahead",
                (false, _) => "unsupported",
            }
            .into(),
            tested_version: PINNED_PI_VERSION.into(),
            workspace_display: self.workspace_display,
            // The Pi bridge reports no directory, and Pi already accepts native control, so
            // there is nothing to promote and nowhere promotion would need to launch.
            workspace_path: None,
            observation: Observation {
                coverage: "partial".into(),
                reason_code: match (compatible, tested) {
                    (true, true) => "pi_extension_ui_partial",
                    // Structurally usable and detected by the bridge, but outside the build
                    // conformance covered. Said plainly rather than passed off as tested.
                    (true, false) => "pi_extension_untested_build",
                    (false, _) => "adapter_version_unsupported",
                }
                .into(),
                last_authoritative_at: None,
            },
            turn: TurnState::Unknown {
                reason_code: "partial_observation".into(),
            },
            capabilities: AgentCapabilities {
                history: "full".into(),
                commands: if compatible {
                    self.commands.into()
                } else {
                    CommandCapabilities::none()
                },
                interactions: InteractionCapabilities::none(),
                pending_rehydration: "current_process".into(),
                terminal_continuity: "unavailable".into(),
            },
            control_owner: "shared".into(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PiBridgeInbound {
    Register(PiBridgeRegister),
    SnapshotStart,
    SnapshotEntry(WireTimelineEntry),
    SnapshotEnd,
    UpsertEntry(WireTimelineEntry),
    Turn(TurnState),
    Capabilities(PiBridgeCommandCapabilities),
    Receipt {
        command_id: String,
        state: String,
        evidence: Option<String>,
        reason_code: Option<String>,
    },
    Shutdown {
        reason: String,
    },
    Unknown,
}

pub(crate) fn decode_pi_bridge_frame(body: &[u8]) -> Result<PiBridgeInbound, AgentProtocolError> {
    let value: Value = decode_agent_body(body)?;
    let message_type = value
        .as_object()
        .and_then(|object| object.get("type"))
        .and_then(Value::as_str)
        .ok_or(AgentProtocolError::MalformedJson)?;
    match message_type {
        "register" => Ok(PiBridgeInbound::Register(
            serde_json::from_value(value).map_err(|_| AgentProtocolError::MalformedJson)?,
        )),
        "snapshot_start" => {
            decode_unit_frame(&value, PI_BRIDGE_PROTOCOL_VERSION, "snapshot_start")?;
            Ok(PiBridgeInbound::SnapshotStart)
        }
        "snapshot_entry" => {
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
            validate_frame_header(
                frame.v,
                PI_BRIDGE_PROTOCOL_VERSION,
                &frame.message_type,
                "snapshot_entry",
            )?;
            Ok(PiBridgeInbound::SnapshotEntry(frame.entry))
        }
        "snapshot_end" => {
            decode_unit_frame(&value, PI_BRIDGE_PROTOCOL_VERSION, "snapshot_end")?;
            Ok(PiBridgeInbound::SnapshotEnd)
        }
        "upsert_entry" => {
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
            validate_frame_header(
                frame.v,
                PI_BRIDGE_PROTOCOL_VERSION,
                &frame.message_type,
                "upsert_entry",
            )?;
            Ok(PiBridgeInbound::UpsertEntry(frame.entry))
        }
        // Same frame, same words, same decoder as every other integration: a turn is one
        // concept, so an adapter contributes only the moment it observed, never its own
        // vocabulary for what working means.
        "turn" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Frame {
                v: u8,
                #[serde(rename = "type")]
                message_type: String,
                state: String,
                #[serde(default)]
                run_id: Option<String>,
                #[serde(default)]
                activity: Option<String>,
            }
            let frame: Frame =
                serde_json::from_value(value).map_err(|_| AgentProtocolError::MalformedJson)?;
            validate_frame_header(
                frame.v,
                PI_BRIDGE_PROTOCOL_VERSION,
                &frame.message_type,
                "turn",
            )?;
            Ok(PiBridgeInbound::Turn(turn_from_bridge_frame(
                &frame.state,
                frame.run_id,
                frame.activity,
            )?))
        }
        "capabilities" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Frame {
                v: u8,
                #[serde(rename = "type")]
                message_type: String,
                commands: PiBridgeCommandCapabilities,
            }
            let frame: Frame =
                serde_json::from_value(value).map_err(|_| AgentProtocolError::MalformedJson)?;
            validate_frame_header(
                frame.v,
                PI_BRIDGE_PROTOCOL_VERSION,
                &frame.message_type,
                "capabilities",
            )?;
            Ok(PiBridgeInbound::Capabilities(frame.commands))
        }
        "command_receipt" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Frame {
                v: u8,
                #[serde(rename = "type")]
                message_type: String,
                command_id: String,
                state: String,
                #[serde(default)]
                evidence: Option<String>,
                #[serde(default)]
                reason_code: Option<String>,
            }
            let frame: Frame =
                serde_json::from_value(value).map_err(|_| AgentProtocolError::MalformedJson)?;
            validate_frame_header(
                frame.v,
                PI_BRIDGE_PROTOCOL_VERSION,
                &frame.message_type,
                "command_receipt",
            )?;
            valid_opaque_id(&frame.command_id)?;
            valid_token(&frame.state)?;
            if let Some(evidence) = &frame.evidence {
                valid_token(evidence)?;
            }
            if let Some(reason) = &frame.reason_code {
                valid_token(reason)?;
            }
            Ok(PiBridgeInbound::Receipt {
                command_id: frame.command_id,
                state: frame.state,
                evidence: frame.evidence,
                reason_code: frame.reason_code,
            })
        }
        "shutdown" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Frame {
                v: u8,
                #[serde(rename = "type")]
                message_type: String,
                reason: String,
            }
            let frame: Frame =
                serde_json::from_value(value).map_err(|_| AgentProtocolError::MalformedJson)?;
            validate_frame_header(
                frame.v,
                PI_BRIDGE_PROTOCOL_VERSION,
                &frame.message_type,
                "shutdown",
            )?;
            valid_token(&frame.reason)?;
            Ok(PiBridgeInbound::Shutdown {
                reason: frame.reason,
            })
        }
        _ => Ok(PiBridgeInbound::Unknown),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum PiBridgeOutbound {
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
        #[serde(skip_serializing_if = "Option::is_none")]
        text: Option<String>,
    },
    Shutdown {
        v: u8,
        reason_code: String,
    },
}

impl PiBridgeOutbound {
    pub(crate) fn registered(session: &RegisteredAgentSession) -> Self {
        Self::Registered {
            v: PI_BRIDGE_PROTOCOL_VERSION,
            session_id: session.session_id.clone(),
            process_generation: session.process_generation,
            snapshot_epoch: session.snapshot_epoch,
        }
    }

    pub(crate) fn command(command: AgentCommand) -> Result<Self, AgentProtocolError> {
        command.validate()?;
        let (kind, text) = match command.kind {
            AgentCommandKind::Prompt { text } => ("prompt", Some(text)),
            AgentCommandKind::Steer { text } => ("steer", Some(text)),
            AgentCommandKind::FollowUp { text } => ("follow_up", Some(text)),
            AgentCommandKind::Interrupt => ("interrupt", None),
            AgentCommandKind::InteractionResponse { .. }
            | AgentCommandKind::SetPermissionMode { .. }
            | AgentCommandKind::SetModel { .. }
            | AgentCommandKind::SetEffort { .. }
            | AgentCommandKind::Unknown => {
                return Err(AgentProtocolError::InvalidValue);
            }
        };
        Ok(Self::Command {
            v: PI_BRIDGE_PROTOCOL_VERSION,
            command_id: command.command_id,
            kind: kind.into(),
            text,
        })
    }
}

impl AttachedAgentAdapter for PiAttachedAdapter {
    fn id(&self) -> &'static str {
        "pi"
    }

    fn accepts_legacy_registration(&self) -> bool {
        true
    }

    fn decode_registration(
        &self,
        body: &[u8],
        peer_process_id: Option<u32>,
    ) -> Result<NormalizedRegistration, AgentProtocolError> {
        let PiBridgeInbound::Register(register) = decode_pi_bridge_frame(body)? else {
            return Err(AgentProtocolError::UnexpectedMessage);
        };
        register.normalize(peer_process_id)
    }

    fn decode_event(&self, body: &[u8]) -> Result<NormalizedAdapterEvent, AgentProtocolError> {
        Ok(match decode_pi_bridge_frame(body)? {
            PiBridgeInbound::Register(_) => NormalizedAdapterEvent::Registration,
            PiBridgeInbound::SnapshotStart => NormalizedAdapterEvent::SnapshotStart,
            PiBridgeInbound::SnapshotEntry(entry) => {
                NormalizedAdapterEvent::SnapshotEntry(entry.normalize()?)
            }
            PiBridgeInbound::SnapshotEnd => NormalizedAdapterEvent::SnapshotEnd,
            PiBridgeInbound::UpsertEntry(entry) => {
                NormalizedAdapterEvent::UpsertEntry(entry.normalize()?)
            }
            PiBridgeInbound::Turn(turn) => NormalizedAdapterEvent::Turn(turn),
            PiBridgeInbound::Capabilities(commands) => {
                NormalizedAdapterEvent::CommandCapabilities(commands.into())
            }
            PiBridgeInbound::Receipt {
                command_id,
                state,
                evidence,
                reason_code,
            } => NormalizedAdapterEvent::CommandReceipt {
                command_id,
                state,
                evidence,
                reason_code,
            },
            PiBridgeInbound::Shutdown { reason: _ } => NormalizedAdapterEvent::Shutdown {
                process_exited: true,
            },
            PiBridgeInbound::Unknown => NormalizedAdapterEvent::Unknown,
        })
    }

    fn registered_frame(
        &self,
        session: &RegisteredAgentSession,
    ) -> Result<Value, AgentProtocolError> {
        serde_json::to_value(PiBridgeOutbound::registered(session))
            .map_err(|_| AgentProtocolError::MalformedJson)
    }

    fn command_frame(&self, command: AgentCommand) -> Result<Value, AgentProtocolError> {
        serde_json::to_value(PiBridgeOutbound::command(command)?)
            .map_err(|_| AgentProtocolError::MalformedJson)
    }

    fn shutdown_frame(&self, reason_code: &str) -> Result<Value, AgentProtocolError> {
        valid_token(reason_code)?;
        serde_json::to_value(PiBridgeOutbound::Shutdown {
            v: PI_BRIDGE_PROTOCOL_VERSION,
            reason_code: reason_code.into(),
        })
        .map_err(|_| AgentProtocolError::MalformedJson)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn register(version: &str, mode: &str) -> PiBridgeRegister {
        PiBridgeRegister {
            v: 1,
            message_type: "register".into(),
            adapter: Some("pi".into()),
            adapter_version: version.into(),
            mode: mode.into(),
            session_id: "fixture-session".into(),
            process_nonce: "0123456789abcdef0123456789abcdef".into(),
            process_id: 42,
            workspace_display: "Fixture workspace".into(),
            commands: PiBridgeCommandCapabilities {
                prompt: true,
                steer: true,
                follow_up: true,
                interrupt: true,
            },
        }
    }

    #[test]
    fn detection_and_tui_mode_gate_native_control_not_an_exact_version() {
        let accepted = register(PINNED_PI_VERSION, "tui")
            .normalize(Some(42))
            .unwrap();
        assert!(accepted.compatible);
        assert!(accepted.capabilities.commands.prompt);

        assert_eq!(accepted.observation.reason_code, "pi_extension_ui_partial");

        // A later patch inside the tested minor is still a tested build.
        let patched = register("0.81.9", "tui").normalize(Some(42)).unwrap();
        assert!(patched.compatible);
        assert_eq!(patched.observation.reason_code, "pi_extension_ui_partial");

        // A minor bump is outside conformance but not outside the API. The bridge only
        // advertises a command after finding the surface for it, so the host honours the
        // advertisement and says plainly that the build is untested.
        let untested = register("0.82.1", "tui").normalize(Some(42)).unwrap();
        assert!(untested.compatible);
        assert!(untested.capabilities.commands.prompt);
        assert_eq!(
            untested.observation.reason_code,
            "pi_extension_untested_build"
        );

        // A bridge that detected nothing is honoured just as exactly: an untested build does
        // not invent capability, it forwards whatever the extension found.
        let mut silent = register("0.82.1", "tui");
        silent.commands = PiBridgeCommandCapabilities {
            prompt: false,
            steer: false,
            follow_up: false,
            interrupt: false,
        };
        assert_eq!(
            silent.normalize(Some(42)).unwrap().capabilities.commands,
            CommandCapabilities::none()
        );

        // Provenance, not coverage, is what now licenses the phone to say "working": a `running`
        // turn must only ever come from a turn frame the adapter sent. Pi observes partially and
        // starts unknown, so nothing claims a run until Pi reports one.
        assert!(
            !register(PINNED_PI_VERSION, "tui")
                .normalize(Some(42))
                .unwrap()
                .turn
                .is_authoritative_working()
        );

        // A declared breaking change still closes the door outright.
        let incompatible = register("1.0.0", "tui").normalize(Some(42)).unwrap();
        assert!(!incompatible.compatible);
        assert_eq!(
            incompatible.capabilities.commands,
            CommandCapabilities::none()
        );
        assert_eq!(
            incompatible.observation.reason_code,
            "adapter_version_unsupported"
        );

        assert!(
            register(PINNED_PI_VERSION, "rpc")
                .normalize(Some(42))
                .is_err()
        );
        assert!(
            register(PINNED_PI_VERSION, "tui")
                .normalize(Some(7))
                .is_err()
        );
        let mut wrong_adapter = register(PINNED_PI_VERSION, "tui");
        wrong_adapter.adapter = Some("claude".into());
        assert!(wrong_adapter.normalize(Some(42)).is_err());
    }

    #[test]
    fn bridge_schema_has_no_generic_command_file_environment_or_credential_path() {
        let command = AgentCommand {
            v: crate::agent_protocol::AGENT_PROTOCOL_VERSION,
            command_id: "command-a".into(),
            session_id: "session-a".into(),
            snapshot_epoch: 1,
            expected_generation: 1,
            expected_revision: None,
            kind: AgentCommandKind::Prompt {
                text: "Synthetic command.".into(),
            },
        };
        let encoded = serde_json::to_string(&PiBridgeOutbound::command(command).unwrap()).unwrap();
        assert!(encoded.contains("\"kind\":\"prompt\""));
        for forbidden in ["argv", "cwd", "environment", "credential", "file", "shell"] {
            assert!(!encoded.contains(forbidden));
        }
        let interaction = AgentCommand {
            v: 1,
            command_id: "command-b".into(),
            session_id: "session-a".into(),
            snapshot_epoch: 1,
            expected_generation: 1,
            expected_revision: None,
            kind: AgentCommandKind::Unknown,
        };
        assert!(PiBridgeOutbound::command(interaction).is_err());
    }

    #[test]
    fn unknown_events_are_categorical_and_objects_are_not_stringified() {
        let unknown = br#"{"v":1,"type":"future_event","private":"synthetic"}"#;
        assert_eq!(
            decode_pi_bridge_frame(unknown).unwrap(),
            PiBridgeInbound::Unknown
        );
        assert_eq!(
            PiAttachedAdapter.decode_event(unknown).unwrap(),
            NormalizedAdapterEvent::Unknown
        );
    }

    #[test]
    fn bridge_entries_enforce_preview_and_frame_bounds() {
        let body = serde_json::json!({
            "v": 1,
            "type": "upsert_entry",
            "entry": {
                "source_id": "source-a",
                "source_revision": 1,
                "timestamp": 1,
                "state": "complete",
                "kind": "tool",
                "body": {
                    "type": "tool",
                    "tool": {
                        "name": "fixture_tool",
                        "status": "complete",
                        "input_preview": "x".repeat(crate::agent_protocol::MAX_TOOL_INPUT_PREVIEW_BYTES + 1)
                    }
                },
                "truncation": { "truncated": false }
            }
        });
        let encoded = serde_json::to_vec(&body).unwrap();
        let PiBridgeInbound::UpsertEntry(entry) = decode_pi_bridge_frame(&encoded).unwrap() else {
            panic!("wrong bridge frame");
        };
        assert!(entry.normalize().is_err());
    }
}
