//! One-shot read of a Codex thread's persisted history (Spec 012 §6).
//!
//! A Codex conversation exists before Ciao is watching it, and `sessionStart` does not fire
//! until a session's *first prompt* — a `codex resume` that is read but not typed into fires no
//! hook at all. Hooks alone therefore show a resumed conversation as empty until the next
//! prompt. `thread/read` fills that in: it answers for a thread whose status is `notLoaded`, so
//! reading takes no ownership and does not disturb the TUI that holds it.
//!
//! Read once, when the session first registers. If it fails, the session keeps its live tail and
//! nothing is claimed — a short timeline is a degradation, a wrong one is a defect.

use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

use serde_json::{Value, json};

use crate::{
    agent_protocol::{
        MAX_TIMELINE_ENTRIES_IN_SNAPSHOT, MAX_TIMELINE_TEXT_BYTES, MAX_TOOL_INPUT_PREVIEW_BYTES,
        MAX_TOOL_RESULT_PREVIEW_BYTES, TimelineBody, ToolTimelineBody,
    },
    agent_session::{AgentSessionSupervisor, NormalizedTimelineEntry},
    codex_adapter::codex_run_id,
    codex_app_server,
    hook_common::{bounded_preview, bounded_text, keyed_digest, no_truncation},
};

const CODEX_HISTORY_DOMAIN: &[u8] = b"ciao-codex-history-v1\0";
/// Ceiling on how much of a long conversation is carried into the timeline. The newest items
/// are kept, because those are what the person is reading when they pick up their phone.
const MAX_HISTORY_ENTRIES: usize = MAX_TIMELINE_ENTRIES_IN_SNAPSHOT;

/// Sessions already read, so a conversation is not re-read on every hook event.
///
/// ponytail: one process-wide set, cleared wholesale when it grows past the ceiling. The cost
/// of a rare re-read is one extra subprocess; per-session eviction would be more code for a
/// cheaper mistake. Swap for an LRU only if re-reads show up in practice.
fn already_read() -> &'static Mutex<HashSet<String>> {
    static ALREADY_READ: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    ALREADY_READ.get_or_init(|| Mutex::new(HashSet::new()))
}

fn claim(session_id: &str, process_generation: u64) -> bool {
    let key = format!("{session_id}:{process_generation}");
    let Ok(mut seen) = already_read().lock() else {
        return false;
    };
    if seen.len() > 512 {
        seen.clear();
    }
    seen.insert(key)
}

/// Reads a Codex thread's history in the background and prepends it to the live session.
///
/// Spawned rather than awaited: the hook that triggered this is holding a connection open with a
/// budget measured against the vendor's own hook timeout, and history is worth a second of
/// nobody's waiting.
///
/// `live_run_id` names the turn the live tail already owns, and it is why this is triggered by
/// the session's first turn rather than by its registration: without a turn to exclude there is
/// no way to tell the conversation-so-far from the message the person just typed.
pub(crate) fn spawn_history_read(
    sessions: AgentSessionSupervisor,
    adoptions: std::sync::Arc<crate::codex_adopted::AdoptionRegistry>,
    session_id: String,
    thread_id: String,
    live_run_id: String,
    process_id: u32,
    process_generation: u64,
) {
    if !claim(&session_id, process_generation) {
        return;
    }
    tokio::spawn(async move {
        let Some(binary) = codex_binary_of(process_id).await else {
            tracing::debug!(
                session = %session_id,
                "the Codex binary running this session could not be resolved; keeping the live tail"
            );
            return;
        };
        // The resolved binary is the registration evidence discovery runs on (Spec 013 §8):
        // proven from a live process, persisted so an unheld thread is reachable after every
        // terminal has closed.
        adoptions.record_binary_evidence(binary.clone());
        let entries = match read_thread(&binary, &thread_id, &live_run_id).await {
            Ok(entries) if entries.is_empty() => return,
            Ok(entries) => entries,
            Err(error) => {
                tracing::debug!(error = %error, "reading Codex thread history failed");
                return;
            }
        };
        let count = entries.len();
        match sessions.prepend_bridge_history(&session_id, entries) {
            Ok(()) => tracing::info!(session = %session_id, count, "Codex history reconciled"),
            Err(error) => tracing::debug!(error = %error, "prepending Codex history failed"),
        }
    });
}

/// The exact binary the observed session is running, taken from the process itself.
///
/// Not a `PATH` lookup: the daemon's environment comes from a service manager and need not
/// contain the user's tool installs at all. Reading it from the process also means the
/// app-server is the same build as the TUI, which is what the version pin is for.
///
/// Linux asks the kernel which image is mapped rather than trusting argv[0]: a TUI started as
/// plain `codex` at a shell carries a relative argv[0], and this lookup refused it (grounded
/// 2026-09-08, 12 of 12 reads), which cost that session its history and this machine its
/// discovery evidence. Other platforms keep the argv[0] reading until an equivalent kernel
/// fact is grounded there.
async fn codex_binary_of(process_id: u32) -> Option<PathBuf> {
    #[cfg(target_os = "linux")]
    let binary = crate::process::installed_executable(process_id).await?;
    #[cfg(not(target_os = "linux"))]
    let binary = PathBuf::from(
        crate::process::command(process_id)
            .await?
            .split_ascii_whitespace()
            .next()?,
    );
    (binary.is_absolute() && binary.file_name()? == "codex").then_some(binary)
}

/// One bounded read of a thread's history for the unheld read-only open (Spec 013 §7).
/// Empty on any failure, logged: a short timeline is a degradation, a refused open was a wall.
pub(crate) async fn read_thread_once(
    binary: &std::path::Path,
    thread_id: &str,
) -> Vec<NormalizedTimelineEntry> {
    match read_thread(binary, thread_id, "").await {
        Ok(entries) => entries,
        Err(error) => {
            tracing::debug!(error = %error, "reading Codex thread for the unheld open failed");
            Vec::new()
        }
    }
}

async fn read_thread(
    binary: &std::path::Path,
    thread_id: &str,
    live_run_id: &str,
) -> anyhow::Result<Vec<NormalizedTimelineEntry>> {
    let result = codex_app_server::request(
        binary,
        "thread/read",
        json!({"threadId": thread_id, "includeTurns": true}),
    )
    .await?;
    Ok(map_thread(&result, live_run_id))
}

/// Maps a `thread/read` response onto canonical entries. Everything the vocabulary does not
/// cover becomes a visible `unsupported` card rather than a silent gap: a step the reader
/// cannot see is worse than one that says it is not understood.
pub(crate) fn map_thread(result: &Value, live_run_id: &str) -> Vec<NormalizedTimelineEntry> {
    let mut entries = Vec::new();
    let turns = result
        .get("thread")
        .and_then(|thread| thread.get("turns"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for turn in turns {
        let turn_id = turn.get("id").and_then(Value::as_str).unwrap_or_default();
        // The turn the live tail owns belongs to the live tail, not to history. Codex persists a
        // prompt the moment it is submitted, so the read picks it up and the message the person
        // just typed lands on screen twice, once from each channel.
        //
        // Excluded by identity, not by status: a turn that is running *right now* reports
        // `completed` or `interrupted` to a separate app-server and never `inProgress`, because
        // live turn state is per-process in exactly the way loaded-ness is. A status filter here
        // reads as a fix and never fires.
        if codex_run_id(turn_id) == live_run_id {
            continue;
        }
        let timestamp = turn
            .get("startedAt")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            .max(1);
        for item in turn
            .get("items")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            if let Some(entry) = map_item(item, turn_id, entries.len(), timestamp) {
                entries.push(entry);
            }
        }
    }
    // The newest end of a long conversation is the part being read.
    if entries.len() > MAX_HISTORY_ENTRIES {
        entries.drain(..entries.len() - MAX_HISTORY_ENTRIES);
    }
    entries
}

fn map_item(
    item: &Value,
    turn_id: &str,
    index: usize,
    timestamp: u64,
) -> Option<NormalizedTimelineEntry> {
    let item_type = item.get("type").and_then(Value::as_str)?;
    // Item IDs restart at `item-1` in every turn, so the turn scopes them. Without that, two
    // turns' first items collide onto one entry and the second overwrites the first.
    let source_id = format!(
        "codex.history.{}",
        keyed_digest(
            CODEX_HISTORY_DOMAIN,
            item_type,
            &format!(
                "{turn_id}\0{}\0{index}",
                item.get("id").and_then(Value::as_str).unwrap_or_default()
            ),
        )
    );
    if !crate::codex_adapter::known_thread_item(item_type) {
        crate::drift::note("codex", "history_item", "unknown_item", item_type, None);
    }
    let projection = (item_type == "functionCallOutput")
        .then(|| function_output(item, true))
        .flatten();
    let (kind, body, truncation) = match item_type {
        "functionCallOutput" if projection.is_some() => {
            let (tool, truncation) = projection.unwrap();
            ("tool", TimelineBody::Tool { tool }, truncation)
        }
        "userMessage" => {
            let (text, truncation) = bounded_text(&content_text(item), MAX_TIMELINE_TEXT_BYTES);
            ("user_message", TimelineBody::Text { text }, truncation)
        }
        "agentMessage" => {
            let text = item.get("text").and_then(Value::as_str).unwrap_or_default();
            let (text, truncation) = bounded_text(text, MAX_TIMELINE_TEXT_BYTES);
            ("assistant_message", TimelineBody::Text { text }, truncation)
        }
        "commandExecution"
        | "fileChange"
        | "mcpToolCall"
        | "dynamicToolCall"
        | "collabAgentToolCall"
        | "webSearch" => {
            let (input_preview, clipped) =
                bounded_preview(Some(item), MAX_TOOL_INPUT_PREVIEW_BYTES);
            (
                "tool",
                TimelineBody::Tool {
                    tool: ToolTimelineBody {
                        name: item_type.into(),
                        status: "completed".into(),
                        input_preview,
                        result_preview: None,
                    },
                },
                if clipped {
                    crate::agent_protocol::Truncation {
                        truncated: true,
                        reason_code: Some("preview_bounded".into()),
                        original_bytes: None,
                    }
                } else {
                    no_truncation()
                },
            )
        }
        // Reasoning, plans, review-mode markers, compaction, and anything Codex adds after this
        // pin. Named categorically so the reader can see that something happened here. A type
        // the pin never listed is additionally tallied as drift (Spec 017 §4.2) — the card says
        // something happened, the ledger says the vendor moved.
        _ => (
            "unsupported",
            TimelineBody::Unsupported {
                reason_code: "codex_history_item".into(),
            },
            no_truncation(),
        ),
    };
    let entry = NormalizedTimelineEntry {
        source_id,
        source_revision: 1,
        timestamp,
        state: "complete".into(),
        kind: kind.into(),
        body,
        truncation,
    };
    entry.validate().ok().map(|()| entry)
}

/// Text-only format projection, not admission of the post-pin item. Callers own novelty,
/// identity and lifecycle. Never retain opaque subtrees or use vendor labels as tokens.
pub(crate) fn function_output(
    item: &Value,
    complete: bool,
) -> Option<(ToolTimelineBody, crate::agent_protocol::Truncation)> {
    use crate::hook_common::{GENEROUS_PREVIEW_STRING_BYTES, MAX_PREVIEW_STRING_BYTES};
    let note = |kind: &str, name: &str| {
        crate::drift::note("codex", "function_call_output", kind, name, None);
    };
    let mut clipped = false;
    let (preview, bounded) = match item.get("output") {
        Some(value @ Value::String(_)) => {
            bounded_preview(Some(value), MAX_TOOL_RESULT_PREVIEW_BYTES)
        }
        Some(Value::Array(blocks)) => {
            let mut selected = Vec::new();
            let mut found = false;
            let mut omitted = false;
            let mut fallback_bytes = 2;
            for block in blocks {
                match block.get("type").and_then(Value::as_str) {
                    Some("input_text") => {
                        let Some(text) = block.get("text").and_then(Value::as_str) else {
                            note("malformed_field", "text");
                            continue;
                        };
                        found = true;
                        if omitted {
                            continue;
                        }
                        // Bound allocation before constructing the selected JSON. If even the
                        // fallback cannot fit, omit the preview, but classify ALL later blocks.
                        let (fallback, _) = bounded_text(text, MAX_PREVIEW_STRING_BYTES);
                        fallback_bytes += serde_json::to_string(&fallback).unwrap().len()
                            + usize::from(!selected.is_empty());
                        if fallback_bytes > MAX_TOOL_RESULT_PREVIEW_BYTES {
                            omitted = true;
                            selected.clear();
                            continue;
                        }
                        let (text, truncation) = bounded_text(text, GENEROUS_PREVIEW_STRING_BYTES);
                        clipped |= truncation.truncated;
                        selected.push(Value::String(text));
                    }
                    Some("input_image" | "input_audio" | "encrypted_content") => {}
                    Some(other) => note("unknown_content", other),
                    None => note(
                        "malformed_field",
                        if block.is_object() {
                            "type"
                        } else {
                            "output_block"
                        },
                    ),
                }
            }
            if !found {
                return None;
            }
            if omitted {
                (None, true)
            } else {
                bounded_preview(Some(&Value::Array(selected)), MAX_TOOL_RESULT_PREVIEW_BYTES)
            }
        }
        _ => {
            note("malformed_field", "output");
            return None;
        }
    };
    let mut truncation = no_truncation();
    if complete && (clipped || bounded) {
        truncation.truncated = true;
        truncation.reason_code = Some("preview_bounded".into());
    }
    Some((
        ToolTimelineBody {
            name: "functionCallOutput".into(),
            status: if complete { "completed" } else { "running" }.into(),
            input_preview: None,
            result_preview: if complete { preview } else { None },
        },
        truncation,
    ))
}

/// A `userMessage` carries `content: [{type: "text", text: "…"}]`.
pub(crate) fn content_text(item: &Value) -> String {
    item.get("content")
        .and_then(Value::as_array)
        .map(|parts| {
            parts
                .iter()
                .filter_map(|part| part.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    #[test]
    fn function_output_projection_privacy_shapes_and_bounds() {
        for output in [
            json!(null),
            json!(42),
            json!({}),
            json!([]),
            json!([{"type":"input_text"}]),
            json!([{"type":"input_text","text":3}]),
            json!([{"type":"input_image","text":"CANARY"}]),
            json!([{"type":"input_audio"}]),
            json!([{"type":"encrypted_content"}]),
            json!([null, {}, {"type":42}, {"type":"ScopeFutureOutputBlock","text":"CANARY"}]),
        ] {
            let item = json!({"type":"functionCallOutput","id":"shape","output":output});
            assert!(function_output(&item, true).is_none());
            assert_eq!(map_item(&item, "turn", 0, 1).unwrap().kind, "unsupported");
        }
        assert!(function_output(&json!({}), true).is_none());
        for output in [json!(""), json!([{"type":"input_text","text":""}])] {
            assert!(function_output(&json!({"output":output}), true).is_some());
        }
        let mixed = json!({"output":[{"type":"input_text","text":"alpha"},
            {"type":"input_image","text":"CANARY","image_url":"CANARY"},
            {"type":"input_audio","audio_url":"CANARY"},
            {"type":"encrypted_content","encrypted_content":"CANARY"},
            {"type":"ScopeFutureOutputBlock","text":"CANARY","payload":"CANARY"},
            null, {}, {"type":42}, {"type":"input_text","text":"omega"}],
            "name":"CANARY", "extra":{"text":"CANARY"}});
        let (tool, truncation) = function_output(&mixed, true).unwrap();
        assert!(!truncation.truncated);
        assert_eq!(
            serde_json::from_str::<Value>(&tool.result_preview.unwrap()).unwrap(),
            json!(["alpha", "omega"])
        );
        let blocks: Vec<Value> = (0..96)
            .map(|i| {
                json!({"type":"input_text",
            "text":format!("{}{i:03}", "a".repeat(240))})
            })
            .collect();
        let (tool, truncation) = function_output(&json!({"output":blocks}), true).unwrap();
        let preview = tool.result_preview.unwrap();
        assert!(preview.len() > MAX_TOOL_INPUT_PREVIEW_BYTES);
        assert!(preview.len() <= MAX_TOOL_RESULT_PREVIEW_BYTES);
        assert!(!truncation.truncated);
        assert!(
            serde_json::from_str::<Value>(&preview).unwrap()[95]
                .as_str()
                .unwrap()
                .ends_with("095")
        );
        for text in [format!("{}é", "a".repeat(2047)), "\"\\\n".repeat(2000)] {
            let (tool, truncation) = function_output(&json!({"output":text}), true).unwrap();
            assert!(truncation.truncated);
            let preview = tool.result_preview.unwrap();
            assert!(preview.len() <= MAX_TOOL_RESULT_PREVIEW_BYTES);
            serde_json::from_str::<Value>(&preview).unwrap();
        }
        let mut blocks = vec![json!({"type":"input_text","text":"a".repeat(240)}); 1000];
        blocks.push(json!({"type":"ScopeFutureAfterBudget","text":"CANARY"}));
        let (tool, truncation) = function_output(&json!({"output":blocks}), true).unwrap();
        assert!(tool.result_preview.is_none());
        assert_eq!(truncation.reason_code.as_deref(), Some("preview_bounded"));
        let ledger = crate::drift::snapshot();
        assert!(
            ledger.vendors["codex"]
                .signatures
                .iter()
                .any(|s| s.name == "ScopeFutureAfterBudget")
        );
        assert!(!serde_json::to_string(&ledger).unwrap().contains("CANARY"));
    }

    #[test]
    fn function_output_history_text() {
        let item =
            json!({"type":"functionCallOutput","id":"scope-result","output":"line one\nline two"});
        let entry = map_item(&item, "turn", 0, 1).unwrap();
        entry.validate().unwrap();
        assert_eq!(entry.kind, "tool");
        let TimelineBody::Tool { tool } = entry.body else {
            panic!("tool")
        };
        assert_eq!(tool.name, "functionCallOutput");
        assert!(tool.input_preview.is_none());
        assert_eq!(
            serde_json::from_str::<Value>(&tool.result_preview.unwrap()).unwrap(),
            item["output"]
        );
    }

    use super::*;

    /// A verbatim `thread/read` response from Codex 0.146.0, captured 2026-08-01.
    fn grounded_response() -> Value {
        json!({
            "thread": {
                "id": "019fbfb4-c091-7541-832e-8a1b9b16d414",
                "status": {"type": "notLoaded"},
                "cliVersion": "0.146.0",
                "turns": [{
                    "id": "019fbfb4-c1db-7242-9196-c260f02c9c9b",
                    "items": [
                        {
                            "type": "userMessage",
                            "id": "item-1",
                            "clientId": null,
                            "content": [{"type": "text", "text": "reply with exactly: ok", "text_elements": []}]
                        },
                        {"type": "agentMessage", "id": "item-2", "text": "ok", "phase": "final_answer", "memoryCitation": null}
                    ],
                    "itemsView": "full",
                    "status": "completed",
                    "startedAt": 1785627722,
                    "completedAt": 1785627727
                }]
            }
        })
    }

    #[test]
    fn a_read_thread_becomes_the_conversation_in_order() {
        let entries = map_thread(&grounded_response(), "codex.turn.none");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].kind, "user_message");
        assert_eq!(
            entries[0].body,
            TimelineBody::Text {
                text: "reply with exactly: ok".into()
            }
        );
        assert_eq!(entries[1].kind, "assistant_message");
        assert_eq!(entries[1].body, TimelineBody::Text { text: "ok".into() });
        assert_eq!(entries[0].timestamp, 1785627722);
        for entry in &entries {
            entry.validate().unwrap();
            assert!(entry.source_id.starts_with("codex.history."));
            // A read must not carry the vendor's own identifiers to the phone.
            assert!(!entry.source_id.contains("019fbfb4"));
        }
    }

    /// Codex persists a prompt the moment it is submitted, so the read picks up the turn the
    /// live tail is already delivering and the message lands on screen twice.
    ///
    /// The first attempt filtered on `status == "inProgress"` and shipped, because it passed a
    /// test written from a captured payload. It never fired: a turn running *right now* reports
    /// `completed` or `interrupted` to a separate app-server, since live turn state is
    /// per-process exactly like loaded-ness. Identity is the only thing that survives that.
    #[test]
    fn the_turn_the_live_tail_owns_is_excluded_by_identity_not_status() {
        let live = codex_run_id("019fbfb4-c1db-7242-9196-c260f02c9c9b");
        assert!(map_thread(&grounded_response(), &live).is_empty());

        // Whatever a live turn claims its status is, identity still excludes it — and every
        // other turn is history regardless of how it ended.
        for status in ["completed", "interrupted", "failed", "inProgress"] {
            let mut response = grounded_response();
            response["thread"]["turns"][0]["status"] = json!(status);
            assert!(map_thread(&response, &live).is_empty(), "{status} is live");
            assert_eq!(
                map_thread(&response, "codex.turn.someotherturn").len(),
                2,
                "{status} is history when it is not the live turn"
            );
        }
    }

    #[test]
    fn item_ids_that_repeat_across_turns_do_not_collide() {
        // Codex numbers items from `item-1` in every turn. Two turns' first items must not
        // land on one entry, or the second silently overwrites the first.
        let mut response = grounded_response();
        let turn = response["thread"]["turns"][0].clone();
        let mut second = turn.clone();
        second["id"] = json!("019fbfb4-second-turn");
        response["thread"]["turns"] = json!([turn, second]);
        let entries = map_thread(&response, "codex.turn.none");
        assert_eq!(entries.len(), 4);
        let unique: std::collections::HashSet<_> =
            entries.iter().map(|entry| &entry.source_id).collect();
        assert_eq!(unique.len(), 4);
    }

    #[test]
    fn an_item_kind_added_after_this_pin_is_visible_rather_than_dropped() {
        let mut response = grounded_response();
        response["thread"]["turns"][0]["items"] = json!([
            {"type": "reasoning", "id": "item-1"},
            {"type": "somethingCodexAddsLater", "id": "item-2"},
            {"type": "commandExecution", "id": "item-3", "command": "echo hello"}
        ]);
        let entries = map_thread(&response, "codex.turn.none");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].kind, "unsupported");
        assert_eq!(entries[1].kind, "unsupported");
        assert_eq!(entries[2].kind, "tool");
        let TimelineBody::Tool { tool } = &entries[2].body else {
            panic!("expected a tool body");
        };
        assert!(tool.input_preview.as_ref().unwrap().contains("echo hello"));
    }

    #[test]
    fn a_long_conversation_keeps_its_newest_end() {
        let mut response = grounded_response();
        let items: Vec<Value> = (0..MAX_HISTORY_ENTRIES * 2)
            .map(|index| json!({"type": "agentMessage", "id": format!("item-{index}"), "text": format!("message {index}")}))
            .collect();
        response["thread"]["turns"][0]["items"] = json!(items);
        let entries = map_thread(&response, "codex.turn.none");
        assert_eq!(entries.len(), MAX_HISTORY_ENTRIES);
        assert_eq!(
            entries.last().unwrap().body,
            TimelineBody::Text {
                text: format!("message {}", MAX_HISTORY_ENTRIES * 2 - 1)
            }
        );
    }

    #[test]
    fn a_response_that_is_not_a_thread_yields_nothing_rather_than_guessing() {
        for hostile in [
            json!({}),
            json!({"thread": {}}),
            json!({"thread": {"turns": "no"}}),
        ] {
            assert!(map_thread(&hostile, "codex.turn.none").is_empty());
        }
    }

    #[test]
    fn a_session_is_only_claimed_once_per_process_generation() {
        assert!(claim("fixture-codex-session", 1));
        assert!(!claim("fixture-codex-session", 1));
        // A restarted TUI is a new generation and a new conversation to fill in.
        assert!(claim("fixture-codex-session", 2));
    }

    /// A shell starts `codex` with a relative argv[0]; the grounded lookup refused exactly that
    /// shape (2026-09-08, 12 of 12 reads), which cost the session its history and the machine
    /// its discovery evidence. The kernel's image is what enrichment runs, and only its durable
    /// pathname — never the process-bound procfs reference — may be spawned later or recorded.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_tui_started_by_bare_name_resolves_to_its_image_and_never_to_a_procfs_reference() {
        use std::os::unix::process::CommandExt;
        let home = tempfile::tempdir().unwrap();
        let binary = home.path().join("codex");
        std::fs::copy("/bin/sleep", &binary).unwrap();
        let installed = binary.canonicalize().unwrap();
        let mut child = std::process::Command::new(&binary)
            .arg0("codex")
            .arg("30")
            .spawn()
            .unwrap();
        let resolved = codex_binary_of(child.id())
            .await
            .expect("a relative argv[0] still names its running image");
        assert_eq!(resolved, installed);
        assert!(
            !resolved.starts_with("/proc"),
            "evidence must outlive the process"
        );
        // An unrelated process keeps its own name; only an image named codex is Codex.
        let mut other = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        assert_eq!(codex_binary_of(other.id()).await, None);
        other.kill().unwrap();
        other.wait().unwrap();
        // An updater that replaced the install leaves the process on its old image: no
        // pathname holds that image any more, so nothing is spawnable later or recordable.
        let replacement = home.path().join("replacement");
        std::fs::copy("/bin/true", &replacement).unwrap();
        std::fs::rename(&replacement, &binary).unwrap();
        assert_eq!(codex_binary_of(child.id()).await, None);
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(codex_binary_of(child.id()).await, None);
    }

    /// Zero model turns, read-only: `CIAO_CODEX_HISTORY_PROBE_PID` names a live, already
    /// authorized staging TUI and `CIAO_CODEX_HISTORY_PROBE_THREAD` its thread. Resolves and
    /// reads exactly the way enrichment does; prints counts and categories only.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "opt-in, read-only: CIAO_CODEX_HISTORY_PROBE_PID and _THREAD name a live TUI"]
    async fn grounded_history_read_resolves_a_live_tui_by_its_running_image() {
        let pid: u32 = std::env::var("CIAO_CODEX_HISTORY_PROBE_PID")
            .expect("an existing TUI pid")
            .parse()
            .expect("a numeric pid");
        let thread = std::env::var("CIAO_CODEX_HISTORY_PROBE_THREAD").expect("its thread id");
        let began = std::time::Instant::now();
        let binary = codex_binary_of(pid)
            .await
            .expect("the running image resolves");
        println!(
            "history_probe resolved_us={} absolute={} basename_codex={} procfs={}",
            began.elapsed().as_micros(),
            binary.is_absolute(),
            binary.file_name().is_some_and(|name| name == "codex"),
            binary.starts_with("/proc")
        );
        let entries = read_thread_once(&binary, &thread).await;
        let mut kinds = std::collections::BTreeMap::new();
        for entry in &entries {
            *kinds.entry(entry.kind.as_str()).or_insert(0usize) += 1;
        }
        println!(
            "history_probe entries={} kinds={kinds:?} elapsed_ms={}",
            entries.len(),
            began.elapsed().as_millis()
        );
        assert!(
            !entries.is_empty(),
            "a conversation with completed turns reads as entries"
        );
    }
}
