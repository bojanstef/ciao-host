//! Turn-to-notification policy shared by the bridge and in-process agent adapters.

use crate::{
    agent_protocol::TurnState,
    agent_session::{AgentSessionSupervisor, unix_now},
    notify::Notifier,
};

/// The one place an alert is raised. Every source funnels through here so that what a phone is
/// told does not depend on which vendor the conversation happens to be with.
///
/// The gate inside `notify` (one push per session per minute, twelve per ten) is what keeps a
/// chatty session from becoming a firehose, so no caller carries its own.
pub(crate) async fn push_attention(
    sessions: &AgentSessionSupervisor,
    notifier: &Notifier,
    session_id: &str,
    kind: &str,
) {
    // Categorical, and the only record that an alert was *attempted*. Without it the sole
    // evidence a push happened is the relay complaining when one fails, so a silent phone and a
    // working relay are indistinguishable from no push at all — which is exactly the hour this
    // rewiring would otherwise have cost the next person. The kind is a validated token; whether
    // the gate then swallowed it is `notify`'s business and deliberately not claimed here.
    tracing::info!(session = %session_id, kind = %kind, "agent session wants attention");
    let facts = sessions
        .notification_facts(session_id)
        .await
        .unwrap_or_default();
    notifier.notify(session_id, &facts, kind, unix_now());
}

/// What a normalized turn edge is worth telling someone, or `None` for one that is nobody's
/// business — a turn that started, or is winding down, is the agent working.
///
/// **This is the adapter-neutral notification.** A vendor hook is a bonus, not the mechanism:
/// Claude Code has one, Codex has one, Pi has none, and before this a Pi session could run all
/// day without ever reaching a pocket. Every adapter reports turns through one normalized
/// vocabulary — `NormalizedAdapterEvent::Turn` — so that vocabulary is what alerts are owed to.
///
/// `Completed { run_id: None }` is deliberately silent: that is the state a session registers
/// *into*, not a turn that ran, and treating it as one buzzes a phone for every reconnect.
pub(crate) fn attention_kind_for_turn(turn: &TurnState) -> Option<&'static str> {
    match turn {
        TurnState::Completed { run_id: Some(_) } => Some("idle_prompt"),
        // Waiting says nothing about permission semantics. Actual permission notifications
        // retain their explicit vendor/interaction kind through the notification path.
        TurnState::AwaitingInteraction { .. } => Some("agent_needs_input"),
        TurnState::Idle
        | TurnState::Completed { run_id: None }
        | TurnState::Running { .. }
        | TurnState::Stopping { .. }
        | TurnState::Interrupted { .. } => None,
        // Interrupted and Failed are both "it stopped without answering", and neither of the
        // kinds this maps to says that: "Awaiting reply" would claim an answer is waiting. They
        // stay silent until there is copy for them rather than borrowing the wrong words.
        TurnState::Failed { .. } => None,
        // Spec 017: vocabulary this build does not recognize is tallied at its parse site, never
        // guessed at here. A state Ciao cannot name is not one it can decide to interrupt for.
        TurnState::Unknown { .. } | TurnState::Unsupported => None,
    }
}
