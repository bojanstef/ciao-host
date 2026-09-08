//! Cross-adapter conformance: one ledger, every production integration.
//!
//! Every per-adapter module already tests its own wire. What none of them could say is whether
//! the five integration paths still agree with each other — which capabilities each one claims,
//! which normalized events its dialect can carry, and which commands its codec will encode. That
//! agreement drifted feature by feature (turn reporting shipped three times, the synthetic-prompt
//! filter once, notifications twice), because nothing failed when a fix covered one surface and
//! skipped the rest.
//!
//! The [`ParityContract`] table below is that agreement, written down. Each row states what one
//! integration supports today, including its known gaps — a gap is a `GAP(parity):` comment on
//! the cell, not an omission. The tests enforce the table in both directions: an adapter that
//! stops honoring a claimed cell fails, and an adapter that quietly gains a capability fails too,
//! until the ledger row (and `docs/audits/2026-08-05-adapter-parity-audit.md`) is updated. Either
//! failure is the point: a change to one integration's surface must name every surface it did not
//! cover.
//!
//! Scope: everything here stays at the codec boundary — registrations, event decode, command
//! encode — where all five paths can be driven identically and deterministically. Live-vendor
//! behaviour stays in the hand-run conformance probes under `integrations/`.

use serde_json::{Value, json};

use crate::{
    agent_adapter::{AdapterConnectionKind, AttachedAgentAdapter, NormalizedAdapterEvent},
    agent_bridge::{AgentAdapterRegistry, PRODUCTION_ADAPTERS},
    agent_protocol::{
        AGENT_PROTOCOL_VERSION, AgentCommand, AgentCommandKind, CommandCapabilities,
        InteractionAnswer, InteractionCapabilities,
    },
    agent_session::{NormalizedRegistration, RegisteredAgentSession},
    codex_adopted::{AdoptParams, adopted_registration},
};

/// The process ID every canonical fixture registers under, passed as its own peer: Pi requires
/// the peer to *be* the registered process, the hook adapters only require that a peer exists.
const CONFORMANCE_PROCESS: u32 = 4242;

/// A normalized event's discriminant, so a ledger row can name what a dialect speaks without
/// carrying payloads. `Registration` and `Unknown` are deliberately absent: both are categorical
/// outcomes every adapter shares, not capabilities one could lack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventKind {
    SnapshotStart,
    SnapshotEntry,
    SnapshotEnd,
    UpsertEntry,
    AppendText,
    Heartbeat,
    SessionEnded,
    CommandCapabilities,
    PermissionMode,
    Model,
    Effort,
    ModelCatalogue,
    CommandReceipt,
    VendorSession,
    Turn,
    UpsertInteraction,
    ResolveInteraction,
    Shutdown,
    Notification,
}

fn kind_of(event: &NormalizedAdapterEvent) -> Option<EventKind> {
    Some(match event {
        NormalizedAdapterEvent::SnapshotStart => EventKind::SnapshotStart,
        NormalizedAdapterEvent::SnapshotEntry(_) => EventKind::SnapshotEntry,
        NormalizedAdapterEvent::SnapshotEnd => EventKind::SnapshotEnd,
        NormalizedAdapterEvent::UpsertEntry(_) => EventKind::UpsertEntry,
        NormalizedAdapterEvent::AppendText(_) => EventKind::AppendText,
        NormalizedAdapterEvent::Heartbeat => EventKind::Heartbeat,
        NormalizedAdapterEvent::SessionEnded => EventKind::SessionEnded,
        NormalizedAdapterEvent::CommandCapabilities(_) => EventKind::CommandCapabilities,
        NormalizedAdapterEvent::PermissionMode(_) => EventKind::PermissionMode,
        NormalizedAdapterEvent::Model(_) => EventKind::Model,
        NormalizedAdapterEvent::Effort(_) => EventKind::Effort,
        NormalizedAdapterEvent::ModelCatalogue(_) => EventKind::ModelCatalogue,
        NormalizedAdapterEvent::CommandReceipt { .. } => EventKind::CommandReceipt,
        NormalizedAdapterEvent::VendorSession(_) => EventKind::VendorSession,
        NormalizedAdapterEvent::Turn(_) => EventKind::Turn,
        NormalizedAdapterEvent::UpsertInteraction(_) => EventKind::UpsertInteraction,
        NormalizedAdapterEvent::ResolveInteraction { .. } => EventKind::ResolveInteraction,
        NormalizedAdapterEvent::Shutdown { .. } => EventKind::Shutdown,
        NormalizedAdapterEvent::Notification(_) => EventKind::Notification,
        NormalizedAdapterEvent::Registration | NormalizedAdapterEvent::Unknown => return None,
    })
}

/// The eight canonical commands, so a ledger row can state exactly which of them a codec encodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandName {
    Prompt,
    Steer,
    FollowUp,
    Interrupt,
    InteractionResponse,
    SetPermissionMode,
    SetModel,
    SetEffort,
}

const ALL_COMMANDS: [CommandName; 8] = [
    CommandName::Prompt,
    CommandName::Steer,
    CommandName::FollowUp,
    CommandName::Interrupt,
    CommandName::InteractionResponse,
    CommandName::SetPermissionMode,
    CommandName::SetModel,
    CommandName::SetEffort,
];

fn command(name: CommandName) -> AgentCommand {
    let kind = match name {
        CommandName::Prompt => AgentCommandKind::Prompt {
            text: "Conformance prompt.".into(),
        },
        CommandName::Steer => AgentCommandKind::Steer {
            text: "Conformance steer.".into(),
        },
        CommandName::FollowUp => AgentCommandKind::FollowUp {
            text: "Conformance follow-up.".into(),
        },
        CommandName::Interrupt => AgentCommandKind::Interrupt,
        CommandName::InteractionResponse => AgentCommandKind::InteractionResponse {
            interaction_id: "interaction-a".into(),
            interaction_revision: 1,
            answer: InteractionAnswer::Choices {
                choice_ids: vec!["deny".into()],
            },
        },
        CommandName::SetPermissionMode => AgentCommandKind::SetPermissionMode {
            mode: "default".into(),
        },
        // Bracketed on purpose: a real model id carries them and the token grammar does not,
        // which is why model ids have a grammar of their own.
        CommandName::SetModel => AgentCommandKind::SetModel {
            model: "claude-opus-5[1m]".into(),
        },
        CommandName::SetEffort => AgentCommandKind::SetEffort {
            effort: "high".into(),
        },
    };
    let agent_command = AgentCommand {
        v: AGENT_PROTOCOL_VERSION,
        command_id: "conformance-command-a".into(),
        session_id: "conformance-session-a".into(),
        snapshot_epoch: 1,
        expected_generation: 1,
        expected_revision: None,
        kind,
    };
    agent_command
        .validate()
        .expect("conformance command fixtures must be canonically valid");
    agent_command
}

fn permits(registration: &NormalizedRegistration, name: CommandName) -> bool {
    registration.capabilities.permits(&command(name).kind)
}

/// One integration path's stated surface. The fields mirror what a phone can observe of the
/// session plus what the daemon relies on structurally; the two function pointers supply the
/// dialect's canonical bytes.
struct ParityContract {
    id: &'static str,
    family: &'static str,
    topology: &'static str,
    connection: AdapterConnectionKind,
    requires_tui: bool,
    accepts_legacy: bool,
    coverage: &'static str,
    control_owner: &'static str,
    history: &'static str,
    pending_rehydration: &'static str,
    /// Whether the canonical registration reports an absolute working directory. Pi's bridge
    /// reports none, which is the structural reason a Pi session can never be promoted.
    reports_workspace_path: bool,
    /// The takeover verb this integration's rows advertise (`agent_session::takeover_verb`),
    /// which the phone renders without inferring anything from the family name.
    takeover: Option<&'static str>,
    commands: CommandCapabilities,
    /// Interaction kinds the pinned registration enables. Everything absent is disabled.
    interactions: &'static [&'static str],
    /// Command kinds `command_frame` encodes. Must be a superset of what the registration
    /// permits: a capability may be gated tighter upstream, but never claimed and unencodable.
    encodes: &'static [CommandName],
    /// Normalized events this dialect has a spelling for. Exactly — no more, no fewer.
    speaks: &'static [EventKind],
    registration: fn() -> Vec<u8>,
    events: fn() -> Vec<(EventKind, Vec<u8>)>,
}

fn frame(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).expect("fixture frames serialize")
}

fn entry_payload() -> Value {
    json!({
        "source_id": "conformance-entry-a",
        "source_revision": 1,
        "timestamp": 1,
        "state": "complete",
        "kind": "assistant_message",
        "body": { "type": "text", "text": "Conformance fixture." },
        "truncation": { "truncated": false, "reason_code": null, "original_bytes": null }
    })
}

fn delta_payload() -> Value {
    json!({
        "source_id": "conformance-entry-a",
        "source_revision": 1,
        "timestamp": 1,
        "kind": "assistant_message",
        "delta": "Conformance delta.",
        "final_chunk": true,
        "truncation": { "truncated": false, "reason_code": null, "original_bytes": null }
    })
}

fn permission_interaction_payload() -> Value {
    json!({
        "interaction_id": "interaction-a",
        "interaction_revision": 1,
        "kind": "permission",
        "created_at": 1_700_000_000_u64,
        "title": "Conformance permission",
        "body": "Conformance bounded body.",
        "response_schema": {
            "type": "choices",
            "minimum": 1,
            "maximum": 1,
            "choices": [
                { "choice_id": "allow-once", "label": "Allow once", "scope": "once" },
                { "choice_id": "deny", "label": "Deny", "scope": "request" },
            ],
        },
    })
}

fn pi_registration() -> Vec<u8> {
    frame(json!({
        "v": 1,
        "type": "register",
        "adapter": "pi",
        "adapter_version": crate::pi_adapter::PINNED_PI_VERSION,
        "mode": "tui",
        "session_id": "conformance-pi-session",
        "process_nonce": "0123456789abcdef0123456789abcdef",
        "process_id": CONFORMANCE_PROCESS,
        "workspace_display": "Conformance workspace",
        "commands": { "prompt": true, "steer": true, "follow_up": true, "interrupt": true }
    }))
}

fn pi_events() -> Vec<(EventKind, Vec<u8>)> {
    vec![
        (
            EventKind::SnapshotStart,
            frame(json!({ "v": 1, "type": "snapshot_start" })),
        ),
        (
            EventKind::SnapshotEntry,
            frame(json!({ "v": 1, "type": "snapshot_entry", "entry": entry_payload() })),
        ),
        (
            EventKind::SnapshotEnd,
            frame(json!({ "v": 1, "type": "snapshot_end" })),
        ),
        (
            EventKind::UpsertEntry,
            frame(json!({ "v": 1, "type": "upsert_entry", "entry": entry_payload() })),
        ),
        (
            EventKind::Turn,
            frame(json!({
                "v": 1, "type": "turn",
                "state": "running", "run_id": "conformance-run-a", "activity": "responding"
            })),
        ),
        (
            EventKind::CommandCapabilities,
            frame(json!({
                "v": 1, "type": "capabilities",
                "commands": { "prompt": true, "steer": true, "follow_up": true, "interrupt": true }
            })),
        ),
        (
            // Decoders pass any token through; the *supervisor* then keeps only
            // accepted | applied | rejected | outcome_unknown (`record_bridge_receipt`) and
            // drops the rest silently — the /status spinner (2026-08-09) was a worker
            // speaking `outcome_unknown` before that word was in the union. An adapter's
            // receipt states must come from the union, not a private vocabulary.
            EventKind::CommandReceipt,
            frame(json!({
                "v": 1, "type": "command_receipt",
                "command_id": "conformance-command-a", "state": "delivered"
            })),
        ),
        (
            EventKind::Shutdown,
            frame(json!({ "v": 1, "type": "shutdown", "reason": "process_exit" })),
        ),
    ]
}

fn claude_registration() -> Vec<u8> {
    frame(json!({
        "v": 1,
        "type": "register",
        "adapter": "claude",
        "adapter_version": crate::claude_adapter::PINNED_CLAUDE_VERSION,
        "mode": "tui_hook",
        "session_id": "conformance-claude-session",
        "process_nonce": "0123456789abcdef0123456789abcdef",
        "process_id": CONFORMANCE_PROCESS,
        "workspace_display": "Conformance workspace",
        "workspace_path": "/private/synthetic/conformance"
    }))
}

fn claude_events() -> Vec<(EventKind, Vec<u8>)> {
    vec![
        (
            EventKind::Heartbeat,
            frame(json!({ "v": 1, "type": "heartbeat" })),
        ),
        (
            EventKind::UpsertEntry,
            frame(json!({ "v": 1, "type": "upsert_entry", "entry": entry_payload() })),
        ),
        (
            EventKind::AppendText,
            frame(json!({ "v": 1, "type": "append_text", "delta": delta_payload() })),
        ),
        (
            EventKind::Notification,
            frame(json!({ "v": 1, "type": "notification", "kind": "permission_prompt" })),
        ),
        (
            EventKind::Turn,
            frame(json!({
                "v": 1, "type": "turn",
                "turn": { "state": "running", "run_id": "conformance-run-a", "activity": "responding" }
            })),
        ),
        (
            EventKind::SessionEnded,
            frame(json!({ "v": 1, "type": "session_end" })),
        ),
    ]
}

fn codex_registration() -> Vec<u8> {
    frame(json!({
        "v": 1,
        "type": "register",
        "adapter": "codex",
        "adapter_version": crate::codex_adapter::PINNED_CODEX_VERSION,
        "mode": "tui_hook",
        "session_id": "conformance-codex-session",
        "process_nonce": "0123456789abcdef0123456789abcdef",
        "process_id": CONFORMANCE_PROCESS,
        "workspace_display": "Conformance workspace",
        "workspace_path": "/private/synthetic/conformance"
    }))
}

fn codex_events() -> Vec<(EventKind, Vec<u8>)> {
    vec![
        (
            EventKind::Heartbeat,
            frame(json!({ "v": 1, "type": "heartbeat" })),
        ),
        (
            EventKind::UpsertEntry,
            frame(json!({ "v": 1, "type": "upsert_entry", "entry": entry_payload() })),
        ),
        (
            EventKind::Notification,
            frame(json!({ "v": 1, "type": "notification", "kind": "permission_prompt" })),
        ),
        // Codex spells a turn as a nested `TurnState`; Pi and the managed worker flatten the
        // same three fields into the frame. One concept, two spellings — a third integration
        // picking either spelling is already covered by this table.
        (
            EventKind::Turn,
            frame(json!({
                "v": 1, "type": "turn",
                "turn": { "state": "running", "run_id": "conformance-run-a", "activity": "responding" }
            })),
        ),
        (
            EventKind::SessionEnded,
            frame(json!({ "v": 1, "type": "session_end" })),
        ),
    ]
}

fn claude_managed_registration() -> Vec<u8> {
    frame(json!({
        "v": 1,
        "type": "register",
        "adapter": "claude-managed",
        "adapter_version": crate::claude_managed_adapter::PINNED_MANAGED_CLI_VERSION,
        "sdk_version": crate::claude_managed_adapter::PINNED_CLAUDE_SDK_VERSION,
        "spawn_token": "0123456789abcdef0123456789abcdef",
        "session_id": "conformance-managed-session",
        "process_nonce": "fedcba9876543210fedcba9876543210",
        "process_id": CONFORMANCE_PROCESS,
        "workspace_display": "Conformance workspace",
        "resumed": false,
        "history_complete": true
    }))
}

fn claude_managed_events() -> Vec<(EventKind, Vec<u8>)> {
    vec![
        (
            EventKind::Heartbeat,
            frame(json!({ "v": 1, "type": "heartbeat" })),
        ),
        (
            EventKind::SnapshotStart,
            frame(json!({ "v": 1, "type": "snapshot_start" })),
        ),
        (
            EventKind::SnapshotEntry,
            frame(json!({ "v": 1, "type": "snapshot_entry", "entry": entry_payload() })),
        ),
        (
            EventKind::SnapshotEnd,
            frame(json!({ "v": 1, "type": "snapshot_end" })),
        ),
        (
            EventKind::UpsertEntry,
            frame(json!({ "v": 1, "type": "upsert_entry", "entry": entry_payload() })),
        ),
        (
            EventKind::AppendText,
            frame(json!({ "v": 1, "type": "append_text", "delta": delta_payload() })),
        ),
        (
            EventKind::CommandCapabilities,
            frame(json!({
                "v": 1, "type": "command_capabilities",
                "prompt": true, "interrupt": true, "permission_mode": true
            })),
        ),
        (
            EventKind::PermissionMode,
            frame(json!({ "v": 1, "type": "permission_mode", "mode": "default" })),
        ),
        (
            // The worker mirrors `valid_model_id` before reporting (worker.mjs
            // MODEL_ID_GRAMMAR): the CLI's synthetic assistant messages carry model
            // "<synthetic>", and one refused frame ends the whole bridge — so the filter has
            // to live on the sending side. Change either grammar only with the other.
            EventKind::Model,
            frame(json!({ "v": 1, "type": "model", "model": "claude-opus-5[1m]" })),
        ),
        (
            EventKind::Effort,
            frame(json!({ "v": 1, "type": "effort", "effort": "high" })),
        ),
        (
            EventKind::ModelCatalogue,
            frame(json!({
                "v": 1, "type": "model_catalogue",
                "models": [{
                    "value": "claude-opus-5[1m]",
                    "display_name": "Opus 5 (1M)",
                    "supports_effort": true,
                    "supported_effort_levels": ["low", "medium", "high", "xhigh", "max"]
                }]
            })),
        ),
        (
            EventKind::CommandReceipt,
            frame(json!({
                "v": 1, "type": "command_receipt",
                "command_id": "conformance-command-a", "state": "delivered"
            })),
        ),
        (
            EventKind::VendorSession,
            frame(json!({
                "v": 1, "type": "vendor_session", "vendor_session_id": "vendor-session-a"
            })),
        ),
        (
            EventKind::Turn,
            frame(json!({
                "v": 1, "type": "turn",
                "state": "running", "run_id": "conformance-run-a", "activity": "responding"
            })),
        ),
        (
            EventKind::UpsertInteraction,
            frame(json!({
                "v": 1, "type": "upsert_interaction", "interaction": permission_interaction_payload()
            })),
        ),
        (
            EventKind::ResolveInteraction,
            frame(json!({
                "v": 1, "type": "resolve_interaction",
                "interaction_id": "interaction-a", "resolution": "answered"
            })),
        ),
        (
            EventKind::Notification,
            frame(json!({ "v": 1, "type": "notification", "kind": "permission_prompt" })),
        ),
        (
            EventKind::SessionEnded,
            frame(json!({ "v": 1, "type": "session_end" })),
        ),
    ]
}

/// The ledger. One row per production adapter, in `PRODUCTION_ADAPTERS` order; the adopted-Codex
/// path is registration-only and has its own test below because it does not implement the trait —
/// itself a `GAP(parity):` recorded in the audit.
fn contracts() -> [ParityContract; 4] {
    [
        ParityContract {
            id: "pi",
            family: "Pi",
            topology: "attached",
            connection: AdapterConnectionKind::PersistentBridge,
            requires_tui: false,
            accepts_legacy: true,
            coverage: "partial",
            control_owner: "shared",
            history: "full",
            pending_rehydration: "current_process",
            // GAP(parity): the Pi bridge reports no workspace path, so a Pi session can never
            // become a managed one.
            reports_workspace_path: false,
            takeover: None,
            commands: CommandCapabilities {
                prompt: true,
                steer: true,
                follow_up: true,
                interrupt: true,
                permission_mode: false,
                // GAP(parity): deliberate and enforced from the extension side — `setModel(` is
                // on the embedded extension's forbidden list, so offering a model switch here
                // would mean widening a command surface Ciao keeps deliberately small.
                model: false,
                effort: false,
            },
            interactions: &[],
            encodes: &[
                CommandName::Prompt,
                CommandName::Steer,
                CommandName::FollowUp,
                CommandName::Interrupt,
            ],
            // GAP(parity): no Notification — a blocked Pi session cannot reach the phone; no
            // AppendText — Pi answers arrive as whole entries, never streamed.
            speaks: &[
                EventKind::SnapshotStart,
                EventKind::SnapshotEntry,
                EventKind::SnapshotEnd,
                EventKind::UpsertEntry,
                EventKind::Turn,
                EventKind::CommandCapabilities,
                EventKind::CommandReceipt,
                EventKind::Shutdown,
            ],
            registration: pi_registration,
            events: pi_events,
        },
        ParityContract {
            id: "claude",
            family: "Claude",
            topology: "attached",
            connection: AdapterConnectionKind::TransientEvent,
            requires_tui: true,
            accepts_legacy: false,
            coverage: "partial",
            control_owner: "terminal",
            history: "live_tail",
            pending_rehydration: "none",
            reports_workspace_path: true,
            takeover: Some("promote"),
            commands: CommandCapabilities::none(),
            interactions: &[],
            encodes: &[],
            speaks: &[
                EventKind::Heartbeat,
                EventKind::UpsertEntry,
                EventKind::AppendText,
                EventKind::Notification,
                EventKind::Turn,
                EventKind::SessionEnded,
            ],
            registration: claude_registration,
            events: claude_events,
        },
        ParityContract {
            id: "claude-managed",
            family: "Claude",
            topology: "managed",
            connection: AdapterConnectionKind::PersistentBridge,
            requires_tui: false,
            accepts_legacy: false,
            coverage: "authoritative",
            control_owner: "none",
            // The current worker maps a complete bounded transcript before registration. A
            // failed/over-bound read advertises live_tail instead; that downgrade is pinned in
            // `claude_managed_adapter` rather than hidden behind this happy-path row.
            history: "full",
            pending_rehydration: "current_process",
            reports_workspace_path: false,
            takeover: None,
            commands: CommandCapabilities {
                prompt: true,
                steer: false,
                follow_up: false,
                interrupt: true,
                permission_mode: true,
                model: true,
                effort: true,
            },
            interactions: &["permission", "question"],
            encodes: &[
                CommandName::Prompt,
                CommandName::Interrupt,
                CommandName::InteractionResponse,
                CommandName::SetPermissionMode,
                CommandName::SetModel,
                CommandName::SetEffort,
            ],
            speaks: &[
                EventKind::Heartbeat,
                EventKind::SnapshotStart,
                EventKind::SnapshotEntry,
                EventKind::SnapshotEnd,
                EventKind::UpsertEntry,
                EventKind::AppendText,
                EventKind::CommandCapabilities,
                EventKind::PermissionMode,
                // The only integration that speaks these: the pinned SDK exposes a live model
                // switch and a flag-settings layer for effort, and publishes the catalogue that
                // makes a picker show real choices rather than compiled-in ones.
                EventKind::Model,
                EventKind::Effort,
                EventKind::ModelCatalogue,
                EventKind::CommandReceipt,
                EventKind::VendorSession,
                EventKind::Turn,
                EventKind::UpsertInteraction,
                EventKind::ResolveInteraction,
                // The worker pushes when it raises a blocking card — the managed half of the
                // notification inversion, closed 2026-08-05.
                EventKind::Notification,
                EventKind::SessionEnded,
            ],
            registration: claude_managed_registration,
            events: claude_managed_events,
        },
        ParityContract {
            id: "codex",
            // 2026-09-08: history/adopted functionCallOutput text projection only.
            // No wire events, capabilities, hook registration or pin membership changed.
            family: "Codex",
            topology: "attached",
            connection: AdapterConnectionKind::TransientEvent,
            requires_tui: true,
            accepts_legacy: false,
            coverage: "partial",
            control_owner: "terminal",
            history: "live_tail",
            pending_rehydration: "none",
            reports_workspace_path: true,
            takeover: Some("pickup"),
            commands: CommandCapabilities::none(),
            interactions: &[],
            encodes: &[],
            // GAP(parity): no AppendText — a Codex answer arrives whole at Stop, never streamed.
            speaks: &[
                EventKind::Heartbeat,
                EventKind::UpsertEntry,
                EventKind::Notification,
                EventKind::Turn,
                EventKind::SessionEnded,
            ],
            registration: codex_registration,
            events: codex_events,
        },
    ]
}

const INTERACTION_KINDS: [&str; 6] = [
    "permission",
    "question",
    "plan_decision",
    "review_decision",
    "elicitation",
    "generic_choice",
];

fn enabled_interactions(interactions: &InteractionCapabilities) -> Vec<&'static str> {
    INTERACTION_KINDS
        .into_iter()
        .zip([
            interactions.permission.enabled,
            interactions.question.enabled,
            interactions.plan_decision.enabled,
            interactions.review_decision.enabled,
            interactions.elicitation.enabled,
            interactions.generic_choice.enabled,
        ])
        .filter_map(|(kind, enabled)| enabled.then_some(kind))
        .collect()
}

fn normalized(contract: &ParityContract) -> NormalizedRegistration {
    let registration = contract
        .adapter()
        .decode_registration(&(contract.registration)(), Some(CONFORMANCE_PROCESS))
        .unwrap_or_else(|error| {
            panic!(
                "{}: the canonical pinned registration must decode, got {error}",
                contract.id
            )
        });
    registration
        .validate()
        .unwrap_or_else(|error| panic!("{}: registration must validate, got {error}", contract.id));
    registration
}

impl ParityContract {
    fn adapter(&self) -> &'static dyn AttachedAgentAdapter {
        PRODUCTION_ADAPTERS
            .iter()
            .copied()
            .find(|adapter| adapter.id() == self.id)
            .unwrap_or_else(|| panic!("ledger row {} has no production adapter", self.id))
    }
}

/// A new adapter cannot join `PRODUCTION_ADAPTERS` without a ledger row, and a row cannot
/// outlive its adapter. This is the hook that makes the rest of the table load-bearing.
#[test]
fn the_ledger_covers_exactly_the_production_adapters() {
    let mut ledger: Vec<&str> = contracts().iter().map(|contract| contract.id).collect();
    let mut production: Vec<&str> = PRODUCTION_ADAPTERS
        .iter()
        .map(|adapter| adapter.id())
        .collect();
    ledger.sort_unstable();
    production.sort_unstable();
    assert_eq!(
        ledger, production,
        "every production adapter needs exactly one parity ledger row; update agent_conformance \
         and docs/audits/2026-08-05-adapter-parity-audit.md together"
    );
}

/// The pinned registration is each integration's whole opening claim; every observable field
/// must match its ledger row. A capability that appears here without a ledger edit is the
/// one-sided-fix failure mode this suite exists to catch.
#[test]
fn every_pinned_registration_matches_its_ledger_row() {
    for contract in contracts() {
        let registration = normalized(&contract);
        let id = contract.id;
        assert_eq!(registration.adapter_family, contract.family, "{id}: family");
        assert_eq!(registration.topology, contract.topology, "{id}: topology");
        assert!(
            registration.compatible,
            "{id}: pinned build must be compatible"
        );
        assert_eq!(
            registration.observation.coverage, contract.coverage,
            "{id}: observation coverage"
        );
        assert_eq!(
            registration.control_owner, contract.control_owner,
            "{id}: control owner"
        );
        assert_eq!(
            registration.capabilities.history, contract.history,
            "{id}: history capability"
        );
        assert_eq!(
            registration.capabilities.pending_rehydration, contract.pending_rehydration,
            "{id}: pending rehydration"
        );
        assert_eq!(
            registration.capabilities.commands, contract.commands,
            "{id}: command capabilities"
        );
        assert_eq!(
            enabled_interactions(&registration.capabilities.interactions),
            contract.interactions,
            "{id}: enabled interaction kinds"
        );
        assert_eq!(
            registration.workspace_path.is_some(),
            contract.reports_workspace_path,
            "{id}: workspace path"
        );
        assert_eq!(
            crate::agent_session::takeover_verb(
                &registration.topology,
                &registration.adapter_family
            ),
            contract.takeover,
            "{id}: takeover verb"
        );
        // Two invariants every integration shares. Spec 005 §1: no registration path may state
        // a working turn — turns travel as their own events. And a canonical fresh registration
        // has no history boundary; `resume` is the resumed-worker case, tested where it lives.
        assert!(
            !registration.turn.is_authoritative_working(),
            "{id}: a registration never states a working turn"
        );
        assert_eq!(
            registration.history_boundary, None,
            "{id}: a fresh registration has no history boundary"
        );
    }
}

/// The adopted-Codex path builds its registration by hand and registers straight with the
/// supervisor instead of implementing the adapter trait, so it gets its own ledger check.
#[test]
fn the_adopted_codex_registration_matches_its_ledger_row() {
    let params = |version: &str| AdoptParams {
        binary: std::path::PathBuf::from("/usr/bin/true"),
        thread_id: "conformance-thread-a".into(),
        rollout: None,
        workspace_display: "Conformance workspace".into(),
        workspace_path: Some("/private/synthetic/conformance".into()),
        adapter_version: version.into(),
    };
    // The surface `model/list` answers on a healthy pickup, and the empty one a failed or
    // refused `model/list` leaves behind. The capability bits must follow the surface, not
    // the build: the same binary honestly advertises the picker on one machine and not on
    // another.
    let offered = crate::codex_adopted::ModelSurface {
        current: Some("gpt-conformance".into()),
        effort: Some("high".into()),
        catalogue: vec![crate::agent_protocol::AgentModelOption {
            value: "gpt-conformance".into(),
            display_name: "Conformance".into(),
            supports_effort: true,
            supported_effort_levels: vec!["low".into(), "high".into()],
        }],
    };
    let registration = adopted_registration(
        &params(crate::codex_adapter::PINNED_CODEX_VERSION),
        &offered,
    );
    registration
        .validate()
        .expect("adopted registration must validate");
    // Mapping-only functionCallOutput extension shares history projection, not this codec.
    assert_eq!(registration.adapter_family, "Codex");
    assert_eq!(registration.topology, "adopted");
    assert_eq!(registration.observation.coverage, "authoritative");
    assert_eq!(registration.control_owner, "none");
    assert_eq!(registration.capabilities.history, "live_tail");
    assert_eq!(
        registration.capabilities.pending_rehydration,
        "current_process"
    );
    assert_eq!(
        registration.capabilities.commands,
        CommandCapabilities {
            prompt: true,
            steer: true,
            follow_up: false,
            interrupt: true,
            // GAP(parity): adopted Codex never restores or reports a permission mode, so a
            // takeover lands in whatever default the app-server picks (managed Claude keeps
            // the mode the conversation already had).
            permission_mode: false,
            // Closed 2026-08-18: the 08-05 audit's "named next pass". The catalogue is
            // `model/list`'s answer at pickup, the write is `thread/settings/update` behind
            // the experimentalApi handshake, and the closed checks live with the adapter
            // (`validate_model_choice` / `validate_effort_choice`).
            model: true,
            effort: true,
        }
    );

    // A vendor that answers `model/list` with nothing — or refuses it — advertises nothing:
    // no picker rather than a picker that does nothing, which was the pre-wiring shape.
    let bare = adopted_registration(
        &params(crate::codex_adapter::PINNED_CODEX_VERSION),
        &crate::codex_adopted::ModelSurface::none(),
    );
    assert!(!bare.capabilities.commands.model);
    assert!(!bare.capabilities.commands.effort);
    assert_eq!(
        enabled_interactions(&registration.capabilities.interactions),
        vec!["permission"]
    );
    assert!(!registration.turn.is_authoritative_working());
    // An adopted conversation is already Ciao's; there is nothing left to take over.
    assert_eq!(
        crate::agent_session::takeover_verb(&registration.topology, &registration.adapter_family),
        None
    );
    // The full thread is backfilled through `thread/resume` at adoption, so there is no unshown
    // history for a boundary to mark. GAP(parity): a very long thread's bounded tail read still
    // goes unmarked — honest marking needs the mapper to say when it truncated.
    assert_eq!(registration.history_boundary, None);

    // The version gate, closed 2026-08-05: a declared-breaking build keeps its readable
    // timeline and loses the write surface, like every other integration. A version Ciao
    // cannot parse does not invent a refusal — `thread/list` defaults absent versions to
    // `unknown`, and refusing those would refuse threads this machine's own pinned Codex
    // wrote. GAP(parity): tightening to the tested-minor bound needs grounded evidence that
    // real rows carry `cliVersion` reliably.
    let breaking = adopted_registration(&params("9.9.9"), &offered);
    breaking
        .validate()
        .expect("a downgraded registration must still validate");
    assert!(!breaking.compatible);
    // A surface was offered, and the version gate still withdraws it with the rest of the
    // write capabilities: a declared-breaking build advertises nothing.
    assert_eq!(breaking.capabilities.commands, CommandCapabilities::none());
    assert_eq!(
        enabled_interactions(&breaking.capabilities.interactions),
        Vec::<&str>::new()
    );
    assert_eq!(
        breaking.observation.reason_code,
        "adapter_version_unsupported"
    );
    let unreadable = adopted_registration(&params("unknown"), &offered);
    assert!(unreadable.compatible);
    assert!(unreadable.capabilities.commands.prompt);
}

/// Both directions of the wire-vocabulary ledger: every spelled event decodes to exactly its
/// normalized kind, and the spelled set is exactly the `speaks` set.
#[test]
fn every_dialect_speaks_exactly_its_ledger_vocabulary() {
    for contract in contracts() {
        let catalog = (contract.events)();
        let mut spoken: Vec<EventKind> = Vec::new();
        for (kind, bytes) in &catalog {
            let event = contract
                .adapter()
                .decode_event(bytes)
                .unwrap_or_else(|error| {
                    panic!(
                        "{}: canonical {kind:?} frame must decode, got {error}",
                        contract.id
                    )
                });
            assert_eq!(
                kind_of(&event),
                Some(*kind),
                "{}: canonical {kind:?} frame decoded to {event:?}",
                contract.id
            );
            assert!(
                !spoken.contains(kind),
                "{}: duplicate {kind:?} in the frame catalog",
                contract.id
            );
            spoken.push(*kind);
        }
        for kind in contract.speaks {
            assert!(
                spoken.contains(kind),
                "{}: ledger says it speaks {kind:?} but the catalog has no frame for it",
                contract.id
            );
        }
        for kind in &spoken {
            assert!(
                contract.speaks.contains(kind),
                "{}: catalog carries {kind:?} but the ledger row does not claim it",
                contract.id
            );
        }
    }
}

/// Every adapter is fed every other dialect's canonical frames. A frame from a foreign dialect
/// may be refused or decode to `Unknown`; what it must never do is decode to a normalized event
/// the receiving adapter's ledger row does not claim. When an integration gains a vocabulary —
/// attached Claude learning `turn`, the managed worker learning `notification` — this fails
/// until the ledger (and the audit doc) says so out loud.
#[test]
fn foreign_dialect_frames_are_never_misread_and_never_widen_a_vocabulary() {
    let table = contracts();
    for receiver in &table {
        for sender in &table {
            for (kind, bytes) in (sender.events)() {
                let Ok(event) = receiver.adapter().decode_event(&bytes) else {
                    continue; // A clean refusal is always acceptable.
                };
                let Some(decoded) = kind_of(&event) else {
                    continue; // Categorical Unknown is the expected answer for a foreign frame.
                };
                assert!(
                    receiver.speaks.contains(&decoded),
                    "{}: decoded a {kind:?} frame from the {} dialect as {decoded:?}, which its \
                     ledger row does not claim — if this vocabulary is new, update the ledger \
                     and docs/audits/2026-08-05-adapter-parity-audit.md",
                    receiver.id,
                    sender.id,
                );
            }
        }
    }
}

/// The command ledger, both directions, plus the one law that must hold everywhere: nothing a
/// registration permits may be unencodable by its own codec.
#[test]
fn every_codec_encodes_exactly_its_ledger_commands() {
    for contract in contracts() {
        for name in ALL_COMMANDS {
            let encoded = contract.adapter().command_frame(command(name));
            assert_eq!(
                encoded.is_ok(),
                contract.encodes.contains(&name),
                "{}: command_frame({name:?}) disagrees with the ledger",
                contract.id
            );
        }
        let registration = normalized(&contract);
        for name in ALL_COMMANDS {
            if permits(&registration, name) {
                assert!(
                    contract.encodes.contains(&name),
                    "{}: the registration permits {name:?} but the codec cannot encode it",
                    contract.id
                );
            }
        }
    }
}

/// Hostile bytes get the same answer from every dialect: a clean error or a categorical
/// non-event. No adapter may panic, and none may mint a session from garbage.
#[test]
fn hostile_bytes_fail_closed_for_every_adapter() {
    let hostile: [&[u8]; 7] = [
        b"",
        b"not json",
        b"[]",
        b"{}",
        br#"{"v": 1}"#,
        br#"{"type": "register"}"#,
        br#"{"v": 99, "type": "zzz_unspecified"}"#,
    ];
    for contract in contracts() {
        for bytes in hostile {
            assert!(
                contract
                    .adapter()
                    .decode_registration(bytes, Some(CONFORMANCE_PROCESS))
                    .is_err(),
                "{}: hostile bytes must never register: {:?}",
                contract.id,
                String::from_utf8_lossy(bytes)
            );
            if let Ok(event) = contract.adapter().decode_event(bytes) {
                assert!(
                    matches!(
                        event,
                        NormalizedAdapterEvent::Unknown | NormalizedAdapterEvent::Registration
                    ),
                    "{}: hostile bytes decoded to {event:?}",
                    contract.id
                );
            }
        }
    }
}

/// Spec 017 §4.6, the rehearsal: input shaped like a future vendor build, derived by mutating
/// every dialect's own canonical frames rather than hand-writing fixtures that rot.
///
/// Two invariants, one per mutation. A canonical envelope whose *type* comes from the future
/// stays categorical — `Unknown`, never an error, never a different event — because that is the
/// degradation the timeline's unsupported card and the drift ledger are built on. A canonical
/// frame that *grew a field* is still refused, because these are Ciao's own hook protocols:
/// tolerance lives at the vendor-payload boundary in the hook processes, and the daemon-side
/// wire stays strict so a compromised or confused hook cannot smuggle width. The one deliberate
/// exception is named where it lives (`unrecognized_event` on the Claude heartbeat), and this
/// test mutates around it.
#[test]
fn future_shaped_input_stays_categorical_and_strict_for_every_dialect() {
    for contract in contracts() {
        let mut registration: Value =
            serde_json::from_slice(&(contract.registration)()).expect("canonical registration");
        registration["field_from_the_future"] = serde_json::json!(true);
        assert!(
            contract
                .adapter()
                .decode_registration(&frame(registration), Some(CONFORMANCE_PROCESS))
                .is_err(),
            "{}: a registration that grew a field must be refused",
            contract.id
        );
        for (kind, bytes) in (contract.events)() {
            let mut retyped: Value = serde_json::from_slice(&bytes).expect("canonical event");
            retyped["type"] = serde_json::json!("frame_from_the_future");
            assert!(
                matches!(
                    contract.adapter().decode_event(&frame(retyped)),
                    Ok(NormalizedAdapterEvent::Unknown)
                ),
                "{}: a {kind:?} envelope with a future type must stay categorical",
                contract.id
            );

            let mut widened: Value = serde_json::from_slice(&bytes).expect("canonical event");
            widened["field_from_the_future"] = serde_json::json!(true);
            assert!(
                contract.adapter().decode_event(&frame(widened)).is_err(),
                "{}: a {kind:?} frame that grew a field must be refused",
                contract.id
            );
        }
    }
}

/// The other half of the rehearsal: where a dialect carries a drift report, the report reaches
/// the ledger and the session machinery sees nothing but a heartbeat. Tolerance without
/// accounting is how silent swallows happen (Spec 017 §4.2).
#[test]
fn drift_reports_are_tallied_and_invisible_for_every_dialect_that_carries_one() {
    let carriers = [
        (
            "claude",
            frame(json!({
                "v": 1,
                "type": "heartbeat",
                "unrecognized_event": "ConformanceFutureHookEvent",
            })),
            "ConformanceFutureHookEvent",
        ),
        (
            "claude-managed",
            frame(json!({
                "v": 1,
                "type": "drift_note",
                "surface": "sdk_stream",
                "name": "ConformanceFutureStreamMessage",
            })),
            "ConformanceFutureStreamMessage",
        ),
    ];
    for (id, bytes, name) in carriers {
        let contract = contracts()
            .into_iter()
            .find(|contract| contract.id == id)
            .expect("carrier dialect has a contract row");
        assert!(
            matches!(
                contract.adapter().decode_event(&bytes),
                Ok(NormalizedAdapterEvent::Heartbeat)
            ),
            "{id}: a drift report is only ever a heartbeat"
        );
        let ledger = crate::drift::snapshot();
        assert!(
            ledger.vendors[id]
                .signatures
                .iter()
                .any(|signature| signature.name == name),
            "{id}: the carried name must reach the ledger"
        );
    }
}

/// Registry dispatch for all four dialects — previously only Pi and attached Claude were ever
/// selected through the production registry in any test.
#[test]
fn the_production_registry_dispatches_every_dialect_to_its_own_codec() {
    for contract in contracts() {
        let selected = AgentAdapterRegistry::production()
            .select(&(contract.registration)(), Some(CONFORMANCE_PROCESS))
            .unwrap_or_else(|error| {
                panic!(
                    "{}: registry must select the dialect, got {error}",
                    contract.id
                )
            });
        assert_eq!(selected.codec.id(), contract.id);
        assert_eq!(selected.registration.adapter_family, contract.family);
    }

    // The one legacy path: a registration with no `adapter` field belongs to Pi alone.
    let mut legacy: Value = serde_json::from_slice(&pi_registration()).expect("fixture json");
    legacy.as_object_mut().expect("object").remove("adapter");
    let selected = AgentAdapterRegistry::production()
        .select(&frame(legacy), Some(CONFORMANCE_PROCESS))
        .expect("legacy registration selects the one legacy-accepting adapter");
    assert_eq!(selected.codec.id(), "pi");

    // An unknown dialect is refused rather than guessed at.
    let mut foreign: Value = serde_json::from_slice(&pi_registration()).expect("fixture json");
    foreign["adapter"] = json!("zsh");
    assert!(
        AgentAdapterRegistry::production()
            .select(&frame(foreign), Some(CONFORMANCE_PROCESS))
            .is_err()
    );
}

/// Structural flags and service frames: the acknowledgement frame exists exactly for transient
/// dialects, and every dialect validates its shutdown reason the same way.
#[test]
fn topology_flags_and_service_frames_match_the_ledger() {
    let session = RegisteredAgentSession {
        session_id: "conformance-session-a".into(),
        process_generation: 1,
        snapshot_epoch: 1,
        disconnect_token: "conformance-disconnect-a".into(),
    };
    for contract in contracts() {
        let adapter = contract.adapter();
        let id = contract.id;
        assert_eq!(
            adapter.connection_kind(),
            contract.connection,
            "{id}: connection kind"
        );
        assert_eq!(
            adapter.requires_tui_process(),
            contract.requires_tui,
            "{id}: TUI requirement"
        );
        assert_eq!(
            adapter.accepts_legacy_registration(),
            contract.accepts_legacy,
            "{id}: legacy registration"
        );
        let registered = adapter
            .registered_frame(&session)
            .unwrap_or_else(|error| panic!("{id}: registered frame must encode, got {error}"));
        assert!(registered.is_object(), "{id}: registered frame is a frame");
        assert_eq!(
            adapter
                .event_applied_frame()
                .unwrap_or_else(|error| panic!("{id}: event_applied must encode, got {error}"))
                .is_some(),
            contract.connection == AdapterConnectionKind::TransientEvent,
            "{id}: the acknowledgement frame belongs to transient dialects exactly"
        );
        assert!(
            adapter.shutdown_frame("session_superseded").is_ok(),
            "{id}: canonical shutdown reason encodes"
        );
        assert!(
            adapter.shutdown_frame("not a token!").is_err(),
            "{id}: a shutdown reason is validated as a token"
        );
    }
}

/// Vendor projection tolerance is separate from the strict canonical-frame suite above.
#[test]
fn future_shaped_input_function_output_projection_and_novelty() {
    assert!(!crate::codex_adapter::known_thread_item(
        "functionCallOutput"
    ));
    let response = json!({"thread":{"turns":[{"id":"scope","items":[
        {"id":"result","type":"functionCallOutput","output":"text"},
        {"id":"reason","type":"reasoning"},
        {"id":"future","type":"ScopeConformanceFutureItem"}
    ]}]}});
    let entries = crate::codex_history::map_thread(&response, "");
    assert_eq!(
        entries.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(),
        vec!["tool", "unsupported", "unsupported"]
    );
    for entry in entries {
        entry.validate().unwrap();
    }
    let ledger = crate::drift::snapshot();
    for name in ["functionCallOutput", "ScopeConformanceFutureItem"] {
        assert!(
            ledger.vendors["codex"]
                .signatures
                .iter()
                .any(|s| s.surface == "history_item" && s.kind == "unknown_item" && s.name == name)
        );
    }
    assert!(
        !ledger.vendors["codex"]
            .signatures
            .iter()
            .any(|s| s.kind == "unknown_item" && s.name == "reasoning")
    );
}
