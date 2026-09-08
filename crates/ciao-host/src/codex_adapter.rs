//! Codex CLI 0.147.0 attached-hook adapter wire (Spec 012).
//!
//! A Ciao-owned hook command converts Codex hook payloads into this bounded local protocol.
//! Raw transcript paths and vendor objects never enter the daemon or the canonical phone wire.
//! Each hook connection carries exactly one event and is authenticated as a descendant of the
//! registered Codex process by `agent_bridge` — Codex, unlike Claude Code, exports no session
//! identity in the hook's environment, so process descent is the whole of the proof.
//!
//! Read-only by construction: no command frame decodes, and the registration advertises no
//! command or interaction capability. Writing to a live Codex thread is refused upstream of
//! this file (Spec 012 §3), not merely unimplemented here.
//!
//! The registration, entry payloads, and service frames are the shared attached-hook shell in
//! `agent_adapter`; what stays here is this dialect's vocabulary — the frames it decodes — and
//! its reason codes. The conformance ledger holds that vocabulary to what this file says.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    agent_adapter::{
        AdapterConnectionKind, AttachedAgentAdapter, AttachedHookDialect, AttachedHookOutbound,
        AttachedHookRegister, NormalizedAdapterEvent, WireTimelineEntry, decode_entry_frame,
        decode_notification_frame, decode_turn_frame, decode_unit_frame, frame_type,
    },
    agent_protocol::{AgentCommand, AgentProtocolError, TurnState},
    agent_session::{NormalizedRegistration, RegisteredAgentSession},
};

pub(crate) const PINNED_CODEX_VERSION: &str = "0.147.0";
pub(crate) const CODEX_HOOK_PROTOCOL_VERSION: u8 = 1;

/// The distilled schema extract this pin was grounded against, embedded so the daemon can tell
/// vendor *novelty* from vendor vocabulary it deliberately ignores (Spec 017 §4.2). Generated
/// by `integrations/codex/generate-conformance.mjs`; regenerated at every pin bump.
pub(crate) const PROTOCOL_PINS: &str =
    include_str!("../../../integrations/codex/conformance/protocol-pins.json");

/// Whether the pin already knew this thread-item type. `false` means the running Codex is
/// producing an item shape newer than this build's grounding — that is drift, where a known
/// type rendered as an unsupported card is a decision.
///
/// Fails safe in the quiet direction: if the embedded extract cannot be read, everything counts
/// as known and nothing is tallied — a broken diagnostic must not invent drift.
pub(crate) fn known_thread_item(item_type: &str) -> bool {
    static KNOWN: std::sync::LazyLock<std::collections::HashSet<String>> =
        std::sync::LazyLock::new(|| {
            #[derive(Deserialize)]
            struct Pins {
                #[serde(rename = "threadItemTypes", default)]
                thread_item_types: Vec<String>,
            }
            serde_json::from_str::<Pins>(PROTOCOL_PINS)
                .map(|pins| pins.thread_item_types.into_iter().collect())
                .unwrap_or_default()
        });
    KNOWN.is_empty() || KNOWN.contains(item_type)
}
/// Separates this vendor's digests from every other adapter's. Frozen: changing it renumbers
/// every live Codex entry.
pub(crate) const CODEX_DIGEST_DOMAIN: &[u8] = b"ciao-codex-hook-v1\0";

const DIALECT: AttachedHookDialect = AttachedHookDialect {
    adapter: "codex",
    family: "Codex",
    pinned_version: PINNED_CODEX_VERSION,
    // The schema-extract verdict (Spec 017 §4.3): a 0.x minor the classifier refuses is
    // admitted as `carried` once this machine has proven its read-set unchanged.
    carry: Some(crate::codex_carry::is_carried),
    protocol_version: CODEX_HOOK_PROTOCOL_VERSION,
    partial_reason: "codex_hooks_partial",
    // Codex does name its own turn boundaries, and they arrive as `Turn` events on their own
    // connection (`codex_hook`) — a registration only says none has been reported yet.
    turn_reason_supported: "codex_turn_unreported",
    turn_reason_unsupported: "adapter_version_unsupported",
};

/// The Ciao run ID for a Codex turn.
///
/// Shared, because two sides have to agree on it: the hook reports turn edges under it, and the
/// history read excludes the turn the live tail owns by comparing it. A vendor turn ID never
/// leaves the host in either direction.
pub(crate) fn codex_run_id(turn_id: &str) -> String {
    format!(
        "codex.turn.{}",
        crate::hook_common::keyed_digest(CODEX_DIGEST_DOMAIN, "turn", turn_id)
    )
}

pub(crate) struct CodexAttachedAdapter;

/// Frames the Codex hook process serializes. This enum is the encode side of the dialect's
/// vocabulary; the decode side is `decode_frame` below, and the two must name the same set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum CodexHookEventFrame {
    Heartbeat {
        v: u8,
    },
    UpsertEntry {
        v: u8,
        // Boxed to keep this enum small: an entry carries a bounded tool preview, and every
        // heartbeat would otherwise pay for the largest variant.
        entry: Box<WireTimelineEntry>,
    },
    /// Codex is blocked on its human and said so. Not timeline content — it never reaches iOS.
    Notification {
        v: u8,
        kind: String,
    },
    /// A turn boundary Codex named itself. Its own frame, because one hook connection carries
    /// exactly one event and a registration is not allowed to state a turn.
    Turn {
        v: u8,
        turn: TurnState,
    },
    SessionEnd {
        v: u8,
    },
}

impl AttachedAgentAdapter for CodexAttachedAdapter {
    fn id(&self) -> &'static str {
        "codex"
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
        let normalized = register.normalize(peer_process_id, &DIALECT)?;
        // First contact (Spec 017 §4.3): an eligible unproven version schedules one bounded
        // background verification; hooks re-register on every event, so a verdict written now
        // admits the very next one. No-op outside the daemon and once judged.
        crate::codex_carry::note_sighting(&normalized.adapter_version);
        Ok(normalized)
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
                decode_unit_frame(&value, CODEX_HOOK_PROTOCOL_VERSION, "heartbeat")?;
                NormalizedAdapterEvent::Heartbeat
            }
            "upsert_entry" => NormalizedAdapterEvent::UpsertEntry(
                decode_entry_frame(value, CODEX_HOOK_PROTOCOL_VERSION, "upsert_entry")?
                    .normalize()?,
            ),
            "notification" => NormalizedAdapterEvent::Notification(decode_notification_frame(
                value,
                CODEX_HOOK_PROTOCOL_VERSION,
            )?),
            "turn" => {
                NormalizedAdapterEvent::Turn(decode_turn_frame(value, CODEX_HOOK_PROTOCOL_VERSION)?)
            }
            "session_end" => {
                decode_unit_frame(&value, CODEX_HOOK_PROTOCOL_VERSION, "session_end")?;
                NormalizedAdapterEvent::SessionEnded
            }
            _ => NormalizedAdapterEvent::Unknown,
        })
    }

    fn registered_frame(
        &self,
        session: &RegisteredAgentSession,
    ) -> Result<Value, AgentProtocolError> {
        AttachedHookOutbound::registered_frame(session, CODEX_HOOK_PROTOCOL_VERSION)
    }

    /// Read-only: there is no command this adapter can carry, and there is no version of it
    /// that quietly grows one. A composer for Codex needs ADR 006 §3–§5 accepted first.
    fn command_frame(&self, _command: AgentCommand) -> Result<Value, AgentProtocolError> {
        Err(AgentProtocolError::UnexpectedMessage)
    }

    fn event_applied_frame(&self) -> Result<Option<Value>, AgentProtocolError> {
        AttachedHookOutbound::event_applied_frame(CODEX_HOOK_PROTOCOL_VERSION)
    }

    fn shutdown_frame(&self, reason_code: &str) -> Result<Value, AgentProtocolError> {
        AttachedHookOutbound::shutdown_frame(reason_code, CODEX_HOOK_PROTOCOL_VERSION)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::agent_protocol::{
        AgentCommandKind, CommandCapabilities, InteractionCapabilities, one_minor_past,
    };

    fn registration(version: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "v": 1,
            "type": "register",
            "adapter": "codex",
            "adapter_version": version,
            "mode": "tui_hook",
            "session_id": "019fbfaf-d4fc-7452-99b7-53b47c5e7e8f",
            "process_nonce": "0123456789abcdef0123456789abcdef",
            "process_id": std::process::id(),
            "workspace_display": "Fixture workspace",
            "workspace_path": "/private/synthetic/Fixture workspace"
        }))
        .unwrap()
    }

    #[test]
    fn pinned_registration_is_read_only_and_attached() {
        let normalized = CodexAttachedAdapter
            .decode_registration(&registration(PINNED_CODEX_VERSION), Some(7))
            .unwrap();
        assert!(normalized.compatible);
        assert_eq!(normalized.adapter_family, "Codex");
        assert_eq!(normalized.topology, "attached");
        assert_eq!(normalized.observation.coverage, "partial");
        assert_eq!(normalized.observation.reason_code, "codex_hooks_partial");
        assert_eq!(normalized.capabilities.history, "live_tail");
        assert_eq!(
            normalized.capabilities.commands,
            CommandCapabilities::none()
        );
        assert_eq!(
            normalized.capabilities.interactions,
            InteractionCapabilities::none()
        );
        assert_eq!(normalized.control_owner, "terminal");
    }

    /// A registration that reported `running` was refused by the supervisor and the connection
    /// closed mid-handshake, so every `UserPromptSubmit` was dropped while `Stop` survived — the
    /// timeline showed the answer and not the question. Spec 005 §1 makes "no registration path
    /// produces a running turn" structural; turns travel as their own event.
    #[test]
    fn a_registration_never_states_a_working_turn() {
        let normalized = CodexAttachedAdapter
            .decode_registration(&registration(PINNED_CODEX_VERSION), Some(7))
            .unwrap();
        assert!(!normalized.turn.is_authoritative_working());
        assert_eq!(
            normalized.turn,
            TurnState::Unknown {
                reason_code: "codex_turn_unreported".into()
            }
        );
        // The invariant the daemon actually enforces: partial observation plus a working turn
        // is refused outright.
        assert!(!normalized.observation.is_authoritative());

        // One minor past the pin, computed instead of spelled: the literal form silently
        // flipped meaning when the pin caught up to it (vendor-version-policy trap #3, retired
        // by Spec 017 §4.6). For a 0.x pin a later minor stays refused until proven; the day
        // Codex crosses 1.0 this case flips to `ahead` by classifier design and fails loudly
        // here, which is the moment to rewrite it deliberately.
        let normalized = CodexAttachedAdapter
            .decode_registration(
                &registration(&one_minor_past(PINNED_CODEX_VERSION)),
                Some(7),
            )
            .unwrap();
        assert!(!normalized.compatible);
        assert_eq!(
            normalized.observation.reason_code,
            "adapter_version_unsupported"
        );
    }

    #[test]
    fn a_turn_arrives_as_its_own_event() {
        let frame = |turn: Value| {
            serde_json::to_vec(&json!({"v": 1, "type": "turn", "turn": turn})).unwrap()
        };
        let running =
            json!({"state": "running", "run_id": "codex.turn.abc", "activity": "responding"});
        assert!(matches!(
            CodexAttachedAdapter.decode_event(&frame(running)).unwrap(),
            NormalizedAdapterEvent::Turn(turn) if turn.is_authoritative_working()
        ));
        assert_eq!(
            CodexAttachedAdapter
                .decode_event(&frame(json!({"state": "completed"})))
                .unwrap(),
            NormalizedAdapterEvent::Turn(TurnState::Completed { run_id: None })
        );
        // A malformed turn is refused rather than decoded to something harmless.
        assert!(
            CodexAttachedAdapter
                .decode_event(&frame(json!({"state": "running"})))
                .is_err()
        );
    }

    #[test]
    fn registration_requires_an_authenticated_peer_and_a_real_process() {
        assert!(
            CodexAttachedAdapter
                .decode_registration(&registration(PINNED_CODEX_VERSION), None)
                .is_err()
        );
        let no_process = serde_json::to_vec(&json!({
            "v": 1, "type": "register", "adapter": "codex",
            "adapter_version": PINNED_CODEX_VERSION, "mode": "tui_hook",
            "session_id": "fixture", "process_nonce": "0123456789abcdef0123456789abcdef",
            "process_id": 0, "workspace_display": "w", "workspace_path": "/tmp"
        }))
        .unwrap();
        assert!(
            CodexAttachedAdapter
                .decode_registration(&no_process, Some(7))
                .is_err()
        );
    }

    #[test]
    fn transient_events_are_strict_and_bounded() {
        let upsert = serde_json::to_vec(&json!({
            "v": 1,
            "type": "upsert_entry",
            "entry": {
                "source_id": "codex.prompt.abc",
                "source_revision": 1,
                "timestamp": 1,
                "state": "complete",
                "kind": "user_message",
                "body": {"type": "text", "text": "Synthetic prompt."},
                "truncation": {"truncated": false, "reason_code": null, "original_bytes": null}
            }
        }))
        .unwrap();
        assert!(matches!(
            CodexAttachedAdapter.decode_event(&upsert).unwrap(),
            NormalizedAdapterEvent::UpsertEntry(_)
        ));

        let malformed = serde_json::to_vec(&json!({
            "v": 1, "type": "heartbeat", "unexpected": true
        }))
        .unwrap();
        assert!(CodexAttachedAdapter.decode_event(&malformed).is_err());

        let wrong_version = serde_json::to_vec(&json!({"v": 2, "type": "heartbeat"})).unwrap();
        assert!(CodexAttachedAdapter.decode_event(&wrong_version).is_err());
    }

    #[test]
    fn a_notification_decodes_to_its_own_event_rather_than_timeline_content() {
        let frame = |kind: Value| {
            serde_json::to_vec(&json!({"v": 1, "type": "notification", "kind": kind})).unwrap()
        };
        assert_eq!(
            CodexAttachedAdapter
                .decode_event(&frame(json!("permission_prompt")))
                .unwrap(),
            NormalizedAdapterEvent::Notification("permission_prompt".into())
        );
        for hostile in [json!("has spaces"), json!(""), json!(7), json!(null)] {
            assert!(CodexAttachedAdapter.decode_event(&frame(hostile)).is_err());
        }
    }

    #[test]
    fn the_adapter_has_no_command_surface_at_all() {
        assert_eq!(
            CodexAttachedAdapter.connection_kind(),
            AdapterConnectionKind::TransientEvent
        );
        assert!(CodexAttachedAdapter.requires_tui_process());
        assert!(
            CodexAttachedAdapter
                .command_frame(AgentCommand {
                    v: 1,
                    command_id: "fixture-command".into(),
                    session_id: "fixture-session".into(),
                    snapshot_epoch: 1,
                    expected_generation: 1,
                    expected_revision: None,
                    kind: AgentCommandKind::Interrupt,
                })
                .is_err()
        );
        assert_eq!(
            CodexAttachedAdapter.event_applied_frame().unwrap(),
            Some(json!({"type": "event_applied", "v": 1}))
        );
    }

    /// The shared registration shell honors a dialect's prover (Spec 017 §4.3): a version the
    /// classifier refuses registers `carried` and compatible when the prover vouches for it.
    /// Proven with a synthetic dialect so no global verdict state leaks between tests; the
    /// real prover's mechanics are `codex_carry`'s own tests.
    #[test]
    fn a_proven_version_registers_carried_through_the_shared_shell() {
        const PROVEN: AttachedHookDialect = AttachedHookDialect {
            carry: Some(|_version| true),
            ..DIALECT
        };
        let register: AttachedHookRegister =
            serde_json::from_slice(&registration(&one_minor_past(PINNED_CODEX_VERSION))).unwrap();
        let normalized = register.normalize(Some(7), &PROVEN).unwrap();
        assert!(normalized.compatible);
        assert_eq!(normalized.version_state, "carried");
        assert_eq!(
            normalized.observation.reason_code, "codex_hooks_partial",
            "carried observes exactly as grounded does"
        );

        const REFUTED: AttachedHookDialect = AttachedHookDialect {
            carry: Some(|_version| false),
            ..DIALECT
        };
        let register: AttachedHookRegister =
            serde_json::from_slice(&registration(&one_minor_past(PINNED_CODEX_VERSION))).unwrap();
        let normalized = register.normalize(Some(7), &REFUTED).unwrap();
        assert!(!normalized.compatible);
        assert_eq!(normalized.version_state, "unsupported");

        const MAJOR_PROOF_IS_IGNORED: AttachedHookDialect = AttachedHookDialect {
            carry: Some(|_version| true),
            ..DIALECT
        };
        let register: AttachedHookRegister =
            serde_json::from_slice(&registration("1.147.0")).unwrap();
        let normalized = register
            .normalize(Some(7), &MAJOR_PROOF_IS_IGNORED)
            .unwrap();
        assert!(
            !normalized.compatible,
            "a prover can vouch for a minor; a major announces changed meanings and stays refused"
        );
    }

    /// The embedded extract must stay readable, or drift tallying silently disarms — this is
    /// the lock that fails if `protocol-pins.json` moves or changes shape.
    #[test]
    fn the_embedded_pin_extract_separates_known_items_from_novel_ones() {
        assert!(
            known_thread_item("agentMessage"),
            "a type the pin lists is vendor vocabulary, not drift"
        );
        assert!(
            known_thread_item("reasoning"),
            "deliberately-unsupported types at the pin are still known"
        );
        assert!(
            !known_thread_item("itemTypeFromAFutureCodex"),
            "an unlisted type is drift; if this fails, the embedded extract did not parse"
        );
    }
}
