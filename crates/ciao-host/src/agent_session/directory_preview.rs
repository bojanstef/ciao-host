//! One contextual line for Home. The task remains separately searchable in recent_prompt.
use super::{LiveSession, TimelineBody, TimelineEntry, TurnState, truncate_on_char_boundary};
use crate::agent_protocol::{
    DirectoryPreview, DirectoryPreviewKind as Kind, MAX_RECENT_PROMPT_BYTES, PendingInteraction,
    ResponseSchema,
};

const PREVIEW_SCAN_BYTES: usize = 8 * 1024;

#[derive(Debug)]
pub(super) struct ObservedReply {
    run: String,
    entry: String,
}

/// A cold history read carries no run identifier. Attribute only a new live row seen while
/// its run was open; an update to an older row cannot claim a newer completion.
pub(super) fn observe_new_entry(session: &mut LiveSession, entry: &TimelineEntry) {
    if entry.kind == "assistant_message"
        && let Some(run) = session.open_run.as_ref().and_then(TurnState::run_id)
    {
        session.directory_reply = Some(ObservedReply {
            run: run.clone(),
            entry: entry.entry_id.clone(),
        });
    }
}

pub(super) fn for_session(session: &LiveSession, turn: &TurnState) -> Option<DirectoryPreview> {
    if matches!(turn, TurnState::AwaitingInteraction { .. }) {
        if let Some(card) = session
            .snapshot
            .pending_interactions
            .iter()
            .find(|card| card.is_unresolved_blocking())
        {
            return Some(from_card(card));
        }
        // Only the descendant projection could have turned a non-waiting parent into a wait.
        if !matches!(session.snapshot.turn, TurnState::AwaitingInteraction { .. })
            && session.snapshot.pending_interactions.is_empty()
        {
            return Some(preview(Kind::SubagentInput, None));
        }
        return None;
    }

    // Only the newest conversational entry can supply the preview. A new prompt supersedes
    // a previous answer, even if the next Stop reports completion without new assistant text.
    let message = session
        .history
        .iter()
        .rev()
        .find(|entry| matches!(entry.kind.as_str(), "user_message" | "assistant_message"))?;
    let TimelineBody::Text { text } = &message.body else {
        return None;
    };
    if message.kind == "user_message" {
        return agent_message(&session.snapshot.adapter.family, text);
    }
    let TurnState::Completed { run_id: Some(run) } = turn else {
        return None;
    };
    let observed = session.directory_reply.as_ref()?;
    if observed.run != *run || observed.entry != message.entry_id {
        return None;
    }
    summary(text).map(|text| DirectoryPreview {
        kind: Kind::Reply,
        text: Some(text),
    })
}

fn from_card(card: &PendingInteraction) -> DirectoryPreview {
    let kind = match card.kind.as_str() {
        "permission" => Kind::Permission,
        "question" => Kind::Question,
        _ => Kind::Decision,
    };
    let question = match &card.response_schema {
        ResponseSchema::Questions { questions } if kind == Kind::Question => {
            questions.first().map(|question| question.prompt.as_str())
        }
        _ => None,
    };
    // Tool arguments, answers, choice IDs and free-form card bodies stay inside the conversation.
    preview(kind, question.or(card.title.as_deref()))
}

/// Recognize the vendor envelope before the directory's first-line projection discards its body.
/// This affects presentation only. Adapter state and the timeline retain their own evidence.
fn agent_message(family: &str, text: &str) -> Option<DirectoryPreview> {
    incoming(family, text).map(|(kind, body)| preview(kind, body))
}

pub(super) fn incoming<'a>(family: &str, text: &'a str) -> Option<(Kind, Option<&'a str>)> {
    let text = text[..text.floor_char_boundary(PREVIEW_SCAN_BYTES)].trim_start();
    if family == "Claude" {
        return text
            .strip_prefix("Another Claude session sent a message:")
            .map(|body| (Kind::AgentMessage, Some(body)));
    }
    if family != "Codex" {
        return None;
    }
    if text.starts_with("<subagent_notification>") {
        return Some((Kind::SubagentUpdate, None));
    }
    let mut lines = text.splitn(5, '\n');
    let kind = match lines.next()?.trim_end() {
        "Message Type: MESSAGE" => Kind::AgentMessage,
        "Message Type: NEW_TASK" => Kind::AgentTask,
        "Message Type: FINAL_ANSWER" => Kind::AgentResult,
        _ => return None,
    };
    lines.next()?.strip_prefix("Task name: ")?;
    lines.next()?.strip_prefix("Sender: ")?;
    (lines.next()?.trim_end() == "Payload:").then(|| (kind, lines.next()))
}

fn preview(kind: Kind, text: Option<&str>) -> DirectoryPreview {
    DirectoryPreview {
        kind,
        text: text.and_then(summary),
    }
}

/// Bound work on a large timeline body and preserve UTF-8 when cutting the transmitted text.
pub(super) fn summary(text: &str) -> Option<String> {
    let head = &text[..text.floor_char_boundary(PREVIEW_SCAN_BYTES)];
    let collapsed = head
        .split(|c: char| c.is_whitespace() || DirectoryPreview::invalid_text_character(c))
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let bounded = truncate_on_char_boundary(&collapsed, MAX_RECENT_PROMPT_BYTES);
    (!bounded.is_empty()).then_some(bounded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn directory_previews_follow_card_schema_and_message_envelopes() {
        let cases: Value = serde_json::from_str(include_str!(
            "../../../../protocol/fixtures/phase4/agent-directory-previews-v1.json"
        ))
        .unwrap();
        let session: Value = serde_json::from_str(include_str!(
            "../../../../protocol/fixtures/phase4/agent-session-v1.json"
        ))
        .unwrap();
        let mut descriptor: crate::agent_protocol::AgentSessionDescriptor =
            serde_json::from_value(session["list"]["sessions"][0].clone()).unwrap();
        for case in cases["text_cases"].as_array().unwrap() {
            let text = case["text"].as_str().unwrap();
            descriptor.context_preview = Some(DirectoryPreview {
                kind: Kind::Reply,
                text: Some(text.into()),
            });
            assert_eq!(descriptor.validate().is_ok(), case["valid"], "{text:?}");
            assert_eq!(summary(text).as_deref(), case["summary"].as_str());
        }
        for case in cases["cards"].as_array().unwrap() {
            let index = case["interaction_case"].as_u64().unwrap() as usize;
            let card: PendingInteraction =
                serde_json::from_value(session["interaction_cases"][index].clone()).unwrap();
            assert_eq!(
                serde_json::to_value(from_card(&card)).unwrap(),
                case["preview"]
            );
        }
        for case in cases["messages"].as_array().unwrap() {
            let mapped = agent_message(
                case["family"].as_str().unwrap(),
                case["message"].as_str().unwrap(),
            )
            .unwrap();
            assert_eq!(serde_json::to_value(mapped).unwrap(), case["preview"]);
        }
        assert!(agent_message("Codex", "Message Type: MESSAGE\nExample code here").is_none());
        assert!(agent_message("Claude", "<subagent_notification>").is_none());
        assert!(agent_message("Codex", "Compare <subagent_notification> to the docs").is_none());
        let bounded = summary(&"🦉 ".repeat(300)).unwrap();
        assert!(bounded.len() <= MAX_RECENT_PROMPT_BYTES);
        assert!(bounded.ends_with('🦉'));
    }
}
