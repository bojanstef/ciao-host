//! Claude Code 2.1.222 attached-hook adapter wire.
//!
//! A Ciao-owned hook command converts Anthropic hook payloads into this bounded local protocol.
//! Raw transcript paths and vendor objects never enter the daemon or the canonical phone wire.
//! Each hook connection carries exactly one event and is authenticated as a descendant of the
//! registered Claude process by `agent_bridge`.
//!
//! The registration, entry payloads, and service frames are the shared attached-hook shell in
//! `agent_adapter`; what stays here is this dialect's vocabulary — the frames it decodes — and
//! its reason codes. The conformance ledger holds that vocabulary to what this file says.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    agent_adapter::{
        AdapterConnectionKind, AttachedAgentAdapter, AttachedHookDialect, AttachedHookOutbound,
        AttachedHookRegister, NormalizedAdapterEvent, WireTextDelta, WireTimelineEntry,
        decode_delta_frame, decode_entry_frame, decode_notification_frame, decode_turn_frame,
        decode_unit_frame, frame_type, validate_frame_header,
    },
    agent_protocol::{AgentCommand, AgentProtocolError, TurnState},
    agent_session::{NormalizedRegistration, RegisteredAgentSession},
};

/// The **floor** for the user's own Claude Code: the oldest build whose hook payloads this
/// adapter is grounded against. It admits that version and every later patch of the same minor.
///
/// Deliberately not the version the managed SDK bundles — see `PINNED_MANAGED_CLI_VERSION`.
/// The two used to be one constant, which meant bumping the managed SDK silently raised this
/// floor and cut off every user sitting between the old value and the new one. A floor that
/// ratchets forward with an unrelated pin is not a floor. Raise this only when the payload
/// grounding actually moves, and never as a side effect of a managed bump.
pub(crate) const PINNED_CLAUDE_VERSION: &str = "2.1.222";
pub(crate) const CLAUDE_HOOK_PROTOCOL_VERSION: u8 = 1;

const DIALECT: AttachedHookDialect = AttachedHookDialect {
    adapter: "claude",
    family: "Claude",
    pinned_version: PINNED_CLAUDE_VERSION,
    // Hooks push JSON at you; there is nothing to interrogate, so nothing can prove a refused
    // version. Claude's tolerant band is `ahead`, by SemVer promise, not by proof.
    carry: None,
    protocol_version: CLAUDE_HOOK_PROTOCOL_VERSION,
    partial_reason: "claude_hooks_partial",
    // Claude names its own turn boundaries — `UserPromptSubmit` opens one and `Stop` closes it —
    // and they arrive as `Turn` events on their own connection (`claude_hook`). A registration
    // only says none has been reported yet (Spec 019).
    turn_reason_supported: "claude_turn_unreported",
    turn_reason_unsupported: "adapter_version_unsupported",
};

pub(crate) struct ClaudeAttachedAdapter;

/// Frames the Claude hook process serializes. This enum is the encode side of the dialect's
/// vocabulary; the decode side is `decode_event` below, and the two must name the same set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ClaudeHookEventFrame {
    Heartbeat {
        v: u8,
        /// The vendor's name for a hook event this build has no mapping for — Spec 017 drift,
        /// riding the frame an unknown event already degrades to instead of a new frame type
        /// (which an older daemon would render as an unsupported card). Absent everywhere
        /// else, so canonical heartbeat bytes are unchanged and an older daemon's strict
        /// decode only ever rejects the one transient event that had something to say.
        #[serde(skip_serializing_if = "Option::is_none")]
        unrecognized_event: Option<String>,
    },
    UpsertEntry {
        v: u8,
        entry: WireTimelineEntry,
    },
    AppendText {
        v: u8,
        delta: WireTextDelta,
    },
    /// Claude Code interrupted the user and named its own reason: `permission_prompt`,
    /// `idle_prompt`, or another vendor token. Not timeline content — it never reaches iOS.
    Notification {
        v: u8,
        kind: String,
    },
    /// A turn boundary Claude named itself. Its own frame, because one hook connection carries
    /// exactly one event and a registration is not allowed to state a turn (Spec 005 §1).
    Turn {
        v: u8,
        turn: TurnState,
    },
    SessionEnd {
        v: u8,
    },
}

/// The heartbeat with its optional drift payload. Strict like every hook frame — the one field
/// beyond the unit shape is the sanitized name of an unrecognized vendor event.
fn decode_heartbeat_frame(value: &Value) -> Result<Option<String>, AgentProtocolError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Frame {
        v: u8,
        #[serde(rename = "type")]
        message_type: String,
        #[serde(default)]
        unrecognized_event: Option<String>,
    }
    let frame: Frame =
        serde_json::from_value(value.clone()).map_err(|_| AgentProtocolError::MalformedJson)?;
    validate_frame_header(
        frame.v,
        CLAUDE_HOOK_PROTOCOL_VERSION,
        &frame.message_type,
        "heartbeat",
    )?;
    Ok(frame.unrecognized_event)
}

impl AttachedAgentAdapter for ClaudeAttachedAdapter {
    fn id(&self) -> &'static str {
        "claude"
    }

    fn connection_kind(&self) -> AdapterConnectionKind {
        AdapterConnectionKind::TransientEvent
    }

    fn requires_tui_process(&self) -> bool {
        true
    }

    fn decode_registration(
        &self,
        body: &[u8],
        peer_process_id: Option<u32>,
    ) -> Result<NormalizedRegistration, AgentProtocolError> {
        let (message_type, value) = frame_type(body)?;
        if message_type != "register" {
            return Err(AgentProtocolError::UnexpectedMessage);
        }
        let register: AttachedHookRegister =
            serde_json::from_value(value).map_err(|_| AgentProtocolError::MalformedJson)?;
        register.normalize(peer_process_id, &DIALECT)
    }

    /// This dialect's whole inbound vocabulary. An arm added here without a conformance ledger
    /// update fails the suite.
    fn decode_event(&self, body: &[u8]) -> Result<NormalizedAdapterEvent, AgentProtocolError> {
        let (message_type, value) = frame_type(body)?;
        Ok(match message_type.as_str() {
            "register" => {
                let _: AttachedHookRegister =
                    serde_json::from_value(value).map_err(|_| AgentProtocolError::MalformedJson)?;
                NormalizedAdapterEvent::Registration
            }
            "heartbeat" => {
                if let Some(name) = decode_heartbeat_frame(&value)? {
                    crate::drift::note("claude", "hook_event", "unknown_event", &name, None);
                }
                NormalizedAdapterEvent::Heartbeat
            }
            "upsert_entry" => NormalizedAdapterEvent::UpsertEntry(
                decode_entry_frame(value, CLAUDE_HOOK_PROTOCOL_VERSION, "upsert_entry")?
                    .normalize()?,
            ),
            "append_text" => NormalizedAdapterEvent::AppendText(
                decode_delta_frame(value, CLAUDE_HOOK_PROTOCOL_VERSION)?.normalize()?,
            ),
            "notification" => NormalizedAdapterEvent::Notification(decode_notification_frame(
                value,
                CLAUDE_HOOK_PROTOCOL_VERSION,
            )?),
            "turn" => NormalizedAdapterEvent::Turn(decode_turn_frame(
                value,
                CLAUDE_HOOK_PROTOCOL_VERSION,
            )?),
            "session_end" => {
                decode_unit_frame(&value, CLAUDE_HOOK_PROTOCOL_VERSION, "session_end")?;
                NormalizedAdapterEvent::SessionEnded
            }
            _ => NormalizedAdapterEvent::Unknown,
        })
    }

    fn registered_frame(
        &self,
        session: &RegisteredAgentSession,
    ) -> Result<Value, AgentProtocolError> {
        AttachedHookOutbound::registered_frame(session, CLAUDE_HOOK_PROTOCOL_VERSION)
    }

    fn command_frame(&self, _command: AgentCommand) -> Result<Value, AgentProtocolError> {
        Err(AgentProtocolError::UnexpectedMessage)
    }

    fn event_applied_frame(&self) -> Result<Option<Value>, AgentProtocolError> {
        AttachedHookOutbound::event_applied_frame(CLAUDE_HOOK_PROTOCOL_VERSION)
    }

    fn shutdown_frame(&self, reason_code: &str) -> Result<Value, AgentProtocolError> {
        AttachedHookOutbound::shutdown_frame(reason_code, CLAUDE_HOOK_PROTOCOL_VERSION)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::agent_protocol::CommandCapabilities;

    fn registration(version: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "v": 1,
            "type": "register",
            "adapter": "claude",
            "adapter_version": version,
            "mode": "tui_hook",
            "session_id": "fixture-claude-session",
            "process_nonce": "0123456789abcdef0123456789abcdef",
            "process_id": std::process::id(),
            "workspace_display": "Fixture workspace",
            "workspace_path": "/private/synthetic/Fixture workspace"
        }))
        .unwrap()
    }

    #[test]
    fn pinned_registration_is_read_only_partial_live_tail() {
        let normalized = ClaudeAttachedAdapter
            .decode_registration(&registration(PINNED_CLAUDE_VERSION), Some(7))
            .unwrap();
        assert!(normalized.compatible);
        assert_eq!(normalized.adapter_family, "Claude");
        assert_eq!(normalized.observation.coverage, "partial");
        assert_eq!(normalized.capabilities.history, "live_tail");
        assert_eq!(
            normalized.capabilities.commands,
            CommandCapabilities::none()
        );
        assert_eq!(normalized.control_owner, "terminal");
    }

    /// Spec 005 §1, arrived at over three attempts and fenced here for the second dialect.
    ///
    /// A registration that reported `running` was refused by the supervisor and the connection
    /// closed mid-handshake, so the event riding with it died too. Turn provenance is structural:
    /// the registration says only that none has been reported yet, and turns travel as their own
    /// event. Spec 019 gave attached Claude those events without touching this.
    #[test]
    fn a_registration_never_states_a_working_turn() {
        let normalized = ClaudeAttachedAdapter
            .decode_registration(&registration(PINNED_CLAUDE_VERSION), Some(7))
            .unwrap();
        assert!(!normalized.turn.is_authoritative_working());
        assert_eq!(
            normalized.turn,
            TurnState::Unknown {
                reason_code: "claude_turn_unreported".into()
            }
        );
        // The invariant the daemon actually enforces: partial observation plus a working turn is
        // refused outright, and a refusal closes the connection.
        assert!(!normalized.observation.is_authoritative());
        let mut working = normalized.clone();
        working.turn = TurnState::Running {
            run_id: "claude.turn.a".into(),
            activity: "responding".into(),
        };
        assert!(working.validate().is_err());

        // An unsupported build says the version is why it reports no turn, rather than blaming
        // its observation coverage for something the gate decided.
        let major = ClaudeAttachedAdapter
            .decode_registration(&registration("3.0.0"), Some(7))
            .unwrap();
        assert_eq!(
            major.turn,
            TurnState::Unknown {
                reason_code: "adapter_version_unsupported".into()
            }
        );
    }

    /// Spec 019. The turn rides its own frame, and an unproven one is refused rather than
    /// degraded into something harmless — a `running` with no run to point at is not a turn.
    #[test]
    fn a_turn_arrives_as_its_own_event() {
        let frame = |turn: Value| {
            serde_json::to_vec(&json!({"v": 1, "type": "turn", "turn": turn})).unwrap()
        };
        let running =
            json!({"state": "running", "run_id": "claude.turn.abc", "activity": "responding"});
        assert!(matches!(
            ClaudeAttachedAdapter.decode_event(&frame(running)).unwrap(),
            NormalizedAdapterEvent::Turn(turn) if turn.is_authoritative_working()
        ));
        assert_eq!(
            ClaudeAttachedAdapter
                .decode_event(&frame(
                    json!({"state": "completed", "run_id": "claude.turn.abc"})
                ))
                .unwrap(),
            NormalizedAdapterEvent::Turn(TurnState::Completed {
                run_id: Some("claude.turn.abc".into()),
            })
        );
        assert_eq!(
            ClaudeAttachedAdapter
                .decode_event(&frame(json!({"state": "completed"})))
                .unwrap(),
            NormalizedAdapterEvent::Turn(TurnState::Completed { run_id: None })
        );
        assert!(
            ClaudeAttachedAdapter
                .decode_event(&frame(json!({"state": "running"})))
                .is_err()
        );
        assert!(
            ClaudeAttachedAdapter
                .decode_event(&frame(json!({"state": "running", "run_id": "has spaces"})))
                .is_err()
        );
    }

    /// Spec 017 Phase 2. `2.2.0` was this suite's must-be-refused case; a later 2.x minor now
    /// registers compatible and labeled `ahead` — the flip is the design, recorded here so it
    /// can never read as an accident. The refused case moves out to the major, where it stays.
    #[test]
    fn a_later_minor_registers_ahead_and_a_major_registers_without_capabilities() {
        let ahead = ClaudeAttachedAdapter
            .decode_registration(&registration("2.2.0"), Some(7))
            .unwrap();
        assert!(ahead.compatible);
        assert_eq!(ahead.version_state, "ahead");
        assert_eq!(ahead.tested_version, PINNED_CLAUDE_VERSION);
        assert_eq!(
            ahead.observation.reason_code, "claude_hooks_partial",
            "ahead observes exactly as grounded does; the label rides elsewhere"
        );

        let major = ClaudeAttachedAdapter
            .decode_registration(&registration("3.0.0"), Some(7))
            .unwrap();
        assert!(!major.compatible);
        assert_eq!(major.version_state, "unsupported");
        assert_eq!(major.observation.reason_code, "adapter_version_unsupported");
        assert_eq!(major.capabilities.commands, CommandCapabilities::none());
    }

    /// The drift-carrying heartbeat: still a plain `Heartbeat` to the session machinery, and
    /// the tally lands in the ledger. A bare heartbeat stays exactly as it was, and any other
    /// extra field is still refused — the frame gained one word, not tolerance for anything.
    #[test]
    fn a_heartbeat_carrying_drift_tallies_and_stays_a_heartbeat() {
        let carrying = serde_json::to_vec(&json!({
            "v": 1,
            "type": "heartbeat",
            "unrecognized_event": "AdapterTestFutureEvent"
        }))
        .unwrap();
        assert!(matches!(
            ClaudeAttachedAdapter.decode_event(&carrying).unwrap(),
            NormalizedAdapterEvent::Heartbeat
        ));
        let ledger = crate::drift::snapshot();
        let claude = &ledger.vendors["claude"];
        let tallied = claude
            .signatures
            .iter()
            .find(|signature| signature.name == "AdapterTestFutureEvent")
            .expect("the carried name reaches the ledger");
        assert_eq!(tallied.surface, "hook_event");
        assert_eq!(tallied.kind, "unknown_event");

        let bare = serde_json::to_vec(&json!({"v": 1, "type": "heartbeat"})).unwrap();
        assert!(matches!(
            ClaudeAttachedAdapter.decode_event(&bare).unwrap(),
            NormalizedAdapterEvent::Heartbeat
        ));
        let stray = serde_json::to_vec(&json!({
            "v": 1,
            "type": "heartbeat",
            "anything_else": true
        }))
        .unwrap();
        assert!(ClaudeAttachedAdapter.decode_event(&stray).is_err());
    }

    #[test]
    fn transient_events_are_strict_and_bounded() {
        let append = serde_json::to_vec(&json!({
            "v": 1,
            "type": "append_text",
            "delta": {
                "source_id": "claude-message-a",
                "source_revision": 1,
                "timestamp": 1,
                "kind": "assistant_message",
                "delta": "Synthetic delta.",
                "final_chunk": true,
                "truncation": {
                    "truncated": false,
                    "reason_code": null,
                    "original_bytes": null
                }
            }
        }))
        .unwrap();
        assert!(matches!(
            ClaudeAttachedAdapter.decode_event(&append).unwrap(),
            NormalizedAdapterEvent::AppendText(_)
        ));

        let malformed = serde_json::to_vec(&json!({
            "v": 1,
            "type": "heartbeat",
            "unexpected": true
        }))
        .unwrap();
        assert!(ClaudeAttachedAdapter.decode_event(&malformed).is_err());
    }

    #[test]
    fn a_notification_decodes_to_its_own_event_rather_than_timeline_content() {
        let frame = |kind: Value| {
            serde_json::to_vec(&json!({"v": 1, "type": "notification", "kind": kind})).unwrap()
        };
        assert_eq!(
            ClaudeAttachedAdapter
                .decode_event(&frame(json!("permission_prompt")))
                .unwrap(),
            NormalizedAdapterEvent::Notification("permission_prompt".into())
        );
        // An unrecognized reason still arrives as a notification: the vendor adds these, and a
        // categorical "unsupported" card is not what a "needs you" signal should become.
        assert_eq!(
            ClaudeAttachedAdapter
                .decode_event(&frame(json!("elicitation_response")))
                .unwrap(),
            NormalizedAdapterEvent::Notification("elicitation_response".into())
        );
        for hostile in [json!("has spaces"), json!(""), json!(7), json!(null)] {
            assert!(ClaudeAttachedAdapter.decode_event(&frame(hostile)).is_err());
        }
        let missing = serde_json::to_vec(&json!({"v": 1, "type": "notification"})).unwrap();
        assert!(ClaudeAttachedAdapter.decode_event(&missing).is_err());
    }

    #[test]
    fn transient_adapter_has_acknowledgement_but_no_command_surface() {
        assert_eq!(
            ClaudeAttachedAdapter.connection_kind(),
            AdapterConnectionKind::TransientEvent
        );
        assert_eq!(
            ClaudeAttachedAdapter.event_applied_frame().unwrap(),
            Some(json!({"type": "event_applied", "v": 1}))
        );
    }
}
