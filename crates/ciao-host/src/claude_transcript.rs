//! Reads the newest human prompt out of Claude's own transcript store.
//!
//! Ciao's timeline knows only what hooks reported while it was watching, so a session whose
//! registration outlived its last prompt has nothing to name itself with: a daemon restart, a
//! `claude --resume`, or a stored managed record whose worker is gone. Claude keeps the
//! conversation on disk regardless, and it is the only remaining place those rows are named.
//!
//! Read-only, and nothing here is persisted. This is the same prompt text the phone already
//! receives over the encrypted stream, reached by a different route — the managed metadata
//! store stays metadata-only because Ciao reads Claude's copy instead of keeping one.

use std::{
    env, fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use serde_json::Value;

use crate::agent_protocol::valid_opaque_id;

/// How much of the tail to scan. Transcripts reach several megabytes, most of it tool
/// results, and only the newest prompt is wanted.
///
/// ponytail: tail-only scan. A session whose last megabyte holds no human prompt reads as
/// unnamed, exactly as it does today — scan the whole file if that ever shows up in practice.
const MAX_TRANSCRIPT_TAIL_BYTES: u64 = 1024 * 1024;

/// The newest human prompt in `vendor_session_id`'s transcript, first line only, bounded to
/// `limit` bytes. `None` whenever the conversation cannot be named from disk, which is not an
/// error: transcript recording is defeatable, and every caller already renders absence.
pub(crate) fn recent_prompt(vendor_session_id: &str, limit: usize) -> Option<String> {
    recent_prompt_in(&claude_projects_dir()?, vendor_session_id, limit)
}

/// Takes the projects directory so tests need no process-wide environment mutation; the crate
/// forbids the `unsafe` block that would require.
fn recent_prompt_in(projects: &Path, vendor_session_id: &str, limit: usize) -> Option<String> {
    let path = transcript_path(projects, vendor_session_id)?;
    let text = read_tail(&path)?;
    // Reverse: the newest prompt wins, and a transcript is append-ordered. The first line is
    // skipped unread — a tail cuts mid-line, and half a JSON object parses as nothing anyway.
    text.lines()
        .rev()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find_map(|entry| human_prompt(&entry))
        .and_then(|prompt| first_line_bounded(&prompt, limit))
}

/// The permission mode `vendor_session_id`'s conversation was last running under.
///
/// A takeover spawns a Ciao-owned worker for a conversation the terminal was already holding,
/// and the worker used to start in `default` no matter what the terminal was in. Someone running
/// `bypassPermissions` at a desk therefore got a session that stopped to ask about every tool
/// call the moment they picked up the phone — the same conversation, behaving differently for no
/// reason the person could see.
///
/// Claude records the mode in the transcript twice over: a dedicated `permission-mode` record
/// when it changes, and inline on every user record. Both are read the same way — newest wins —
/// so this needs no hook plumbing and no new frame, only the file Ciao already opens to name
/// these rows.
pub(crate) fn recent_permission_mode(vendor_session_id: &str) -> Option<String> {
    recent_permission_mode_in(&claude_projects_dir()?, vendor_session_id)
}

fn recent_permission_mode_in(projects: &Path, vendor_session_id: &str) -> Option<String> {
    let path = transcript_path(projects, vendor_session_id)?;
    let text = read_tail(&path)?;
    text.lines()
        .rev()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find_map(|entry| {
            let mode = entry.get("permissionMode")?.as_str()?;
            if !crate::agent_protocol::valid_permission_mode(mode) {
                // A mode outside the pinned union is skipped (an older record wins), and that
                // skip is drift worth tallying: a takeover resumed under it would behave
                // differently than the terminal did (Spec 017 §4.2).
                crate::drift::note("claude", "transcript", "unknown_enum", mode, None);
                return None;
            }
            Some(mode.to_owned())
        })
}

/// The model `vendor_session_id`'s conversation was last answered by.
///
/// Same problem as the mode above and the same fix: a takeover used to drop the conversation
/// onto whatever model the worker defaulted to, so picking the phone up could silently change
/// which model was answering mid-conversation. Claude records the model on every assistant
/// record — `message.model` — so newest-wins over the same tail read already being done says
/// what to resume into, with no hook plumbing and no extra file.
///
/// Validated as a *grammar*, not against a list. A transcript can name a model this build has
/// never heard of — it was written by a newer Claude, or by one the account has since been
/// given — and refusing those would resume the conversation onto a different model than the one
/// it was having, which is the exact bug this exists to prevent.
///
/// Effort is deliberately not read back, though the transcript does record it. The persistable
/// settings union excludes `max`, so an inherited `max` could not be expressed the same way it
/// was set, and a resume that silently downgraded effort would be a quieter version of this
/// same bug. Carrying it needs a decision about that asymmetry, not just a second reader.
pub(crate) fn recent_model(vendor_session_id: &str) -> Option<String> {
    recent_model_in(&claude_projects_dir()?, vendor_session_id)
}

fn recent_model_in(projects: &Path, vendor_session_id: &str) -> Option<String> {
    let path = transcript_path(projects, vendor_session_id)?;
    let text = read_tail(&path)?;
    text.lines()
        .rev()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find_map(|entry| {
            let model = entry.get("message")?.get("model")?.as_str()?;
            if crate::agent_protocol::valid_model_id(model).is_err() {
                // Models are grammar-checked, never list-checked, so failing the *grammar*
                // means the vendor changed what a model id looks like. The id itself is not
                // repeated: a string that failed validation is not trusted as a name.
                crate::drift::note("claude", "transcript", "invalid", "model_id", None);
                return None;
            }
            Some(model.to_owned())
        })
}

/// Located by search rather than derived. Claude's project directory name is its own encoding
/// of the workspace path, a rule Ciao does not own and must not reimplement. Session IDs are
/// unique, so asking each project directory whether it holds this one needs no such rule.
fn transcript_path(projects: &Path, vendor_session_id: &str) -> Option<PathBuf> {
    // Rejects a separator, so the join below cannot leave the directory it is given.
    valid_opaque_id(vendor_session_id).ok()?;
    let file_name = format!("{vendor_session_id}.jsonl");
    fs::read_dir(projects)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path().join(&file_name))
        .find(|candidate| candidate.is_file())
}

/// The same two sources `claude_integration` resolves the plugin directory from, so an
/// operator who relocated Claude's config keeps working without configuring Ciao twice.
fn claude_projects_dir() -> Option<PathBuf> {
    let config = match env::var_os("CLAUDE_CONFIG_DIR") {
        Some(value) if !value.is_empty() => {
            let path = PathBuf::from(value);
            path.is_absolute().then_some(path)?
        }
        _ => PathBuf::from(env::var_os("HOME")?).join(".claude"),
    };
    Some(config.join("projects"))
}

fn read_tail(path: &Path) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let length = file.metadata().ok()?.len();
    let offset = length.saturating_sub(MAX_TRANSCRIPT_TAIL_BYTES);
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_TRANSCRIPT_TAIL_BYTES)
        .read_to_end(&mut bytes)
        .ok()?;
    // Lossy: a tail cuts mid-scalar, and the damage is confined to the line already skipped.
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// A transcript's `user` entries are mostly not prompts: tool results, injected reminders, and
/// slash-command wrappers all arrive under the same type. `promptSource` is what separates
/// them — present for anything a person or Ciao submitted (`typed`, `queued`,
/// `suggestion_accepted`, `sdk`), absent for machinery, and `system` for notifications
/// delivered as if the user had spoken.
fn human_prompt(entry: &Value) -> Option<String> {
    if entry.get("type").and_then(Value::as_str) != Some("user") {
        return None;
    }
    match entry.get("promptSource").and_then(Value::as_str) {
        None | Some("system") => return None,
        Some(_) => {}
    }
    let content = entry.get("message")?.get("content")?;
    // A prompt is a string, or the text blocks of a content array.
    match content {
        Value::String(text) => Some(text.clone()),
        Value::Array(blocks) => {
            let text: Vec<_> = blocks
                .iter()
                .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
                .filter_map(|block| block.get("text").and_then(Value::as_str))
                .collect();
            (!text.is_empty()).then(|| text.join("\n"))
        }
        _ => None,
    }
}

/// Matches what the hook path already does to a prompt it reports live, so a row does not
/// change shape depending on which route named it.
fn first_line_bounded(text: &str, limit: usize) -> Option<String> {
    let line = text.lines().find(|line| !line.trim().is_empty())?.trim();
    let bounded = crate::agent_session::truncate_on_char_boundary(line, limit);
    (!bounded.is_empty()).then_some(bounded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// Every shape a real transcript puts under `type: "user"`, newest last.
    fn transcript() -> String {
        [
            r#"{"type":"user","promptSource":"typed","message":{"role":"user","content":"the first thing I asked"}}"#,
            r#"{"type":"user","promptSource":"typed","message":{"role":"user","content":[{"type":"text","text":"asked in blocks"}]}}"#,
            r#"{"type":"assistant","message":{"role":"assistant","content":"working on it"}}"#,
            r#"{"type":"user","message":{"role":"user","content":[{"type":"tool_result","content":"ok"}]}}"#,
            r#"{"type":"user","isMeta":true,"message":{"role":"user","content":"<local-command-caveat>ignore me"}}"#,
            r#"{"type":"user","message":{"role":"user","content":"<command-name>/clear</command-name>"}}"#,
            r#"{"type":"user","promptSource":"system","origin":{"kind":"task-notification"},"message":{"role":"user","content":"<task-notification>done"}}"#,
        ]
        .join("\n")
    }

    /// Nested one directory deep, as Claude's own store is: the reader must search the project
    /// directories rather than expect the transcript at the root.
    fn write_transcript(projects: &Path, session: &str, body: &str) -> PathBuf {
        let project = projects.join("-Users-someone-work");
        fs::create_dir_all(&project).unwrap();
        let mut file = fs::File::create(project.join(format!("{session}.jsonl"))).unwrap();
        file.write_all(body.as_bytes()).unwrap();
        projects.to_path_buf()
    }

    #[test]
    fn names_a_session_from_the_newest_human_prompt() {
        let root = tempfile::tempdir().unwrap();
        let projects = write_transcript(root.path(), "session-one", &transcript());
        // Not the tool result, not the caveat, not the slash command, not the notification.
        assert_eq!(
            recent_prompt_in(&projects, "session-one", 200).as_deref(),
            Some("asked in blocks")
        );
    }

    /// Both shapes Claude writes the mode in, plus a change part-way through and a value from
    /// no vocabulary Ciao knows.
    #[test]
    fn reads_the_mode_the_conversation_was_last_running_under() {
        let root = tempfile::tempdir().unwrap();
        let body = [
            r#"{"type":"permission-mode","permissionMode":"default","sessionId":"s"}"#,
            r#"{"type":"user","permissionMode":"default","message":{"role":"user","content":"hi"}}"#,
            r#"{"type":"permission-mode","permissionMode":"bypassPermissions","sessionId":"s"}"#,
            r#"{"type":"assistant","message":{"role":"assistant","content":"ok"}}"#,
        ]
        .join("\n");
        let projects = write_transcript(root.path(), "session-mode", &body);
        assert_eq!(
            recent_permission_mode_in(&projects, "session-mode").as_deref(),
            Some("bypassPermissions"),
            "newest wins, and a dedicated record counts as much as an inline one"
        );

        // A mode outside the pinned SDK's union is unreadable rather than forwarded: a promoted
        // worker must never be handed a permission it was not deliberately taught.
        let invented = format!(
            "{body}\n{}",
            r#"{"type":"permission-mode","permissionMode":"yolo","sessionId":"s"}"#
        );
        let projects = write_transcript(root.path(), "session-invented", &invented);
        assert_eq!(
            recent_permission_mode_in(&projects, "session-invented").as_deref(),
            Some("bypassPermissions"),
            "an unknown mode is skipped, not passed through and not fatal"
        );

        // A conversation that never recorded one is absent, not defaulted here: the caller
        // decides what an unknown mode means.
        let projects = write_transcript(root.path(), "session-silent", &transcript());
        assert_eq!(recent_permission_mode_in(&projects, "session-silent"), None);
    }

    #[test]
    fn absent_when_no_transcript_holds_the_session() {
        let root = tempfile::tempdir().unwrap();
        let projects = write_transcript(root.path(), "session-one", &transcript());
        assert_eq!(recent_prompt_in(&projects, "session-two", 200), None);
    }

    #[test]
    fn absent_when_every_entry_is_machinery() {
        let root = tempfile::tempdir().unwrap();
        let machinery = transcript()
            .lines()
            .filter(|line| !line.contains(r#""promptSource":"typed""#))
            .collect::<Vec<_>>()
            .join("\n");
        let projects = write_transcript(root.path(), "session-three", &machinery);
        assert_eq!(recent_prompt_in(&projects, "session-three", 200), None);
    }

    #[test]
    fn refuses_a_session_id_that_is_not_an_opaque_id() {
        let root = tempfile::tempdir().unwrap();
        let projects = write_transcript(root.path(), "session-one", &transcript());
        assert_eq!(recent_prompt_in(&projects, "../session-one", 200), None);
    }

    #[test]
    fn reports_only_the_first_line_bounded() {
        let root = tempfile::tempdir().unwrap();
        let long = "x".repeat(400);
        let projects = write_transcript(
            root.path(),
            "session-four",
            &format!(
                r#"{{"type":"user","promptSource":"typed","message":{{"role":"user","content":"\n\n{long}\nsecond line"}}}}"#
            ),
        );
        assert_eq!(
            recent_prompt_in(&projects, "session-four", 200).unwrap(),
            "x".repeat(200)
        );
    }

    /// A transcript larger than the tail bound still names itself from its newest prompt.
    #[test]
    fn scans_the_tail_of_an_oversized_transcript() {
        let root = tempfile::tempdir().unwrap();
        let filler = format!(
            r#"{{"type":"user","message":{{"role":"user","content":[{{"type":"tool_result","content":"{}"}}]}}}}"#,
            "f".repeat(4096)
        );
        let mut body = vec![
            r#"{"type":"user","promptSource":"typed","message":{"role":"user","content":"buried past the tail bound"}}"#
                .to_string(),
        ];
        for _ in 0..300 {
            body.push(filler.clone());
        }
        body.push(
            r#"{"type":"user","promptSource":"queued","message":{"role":"user","content":"within the tail"}}"#
                .to_string(),
        );
        let projects = write_transcript(root.path(), "session-five", &body.join("\n"));
        assert_eq!(
            recent_prompt_in(&projects, "session-five", 200).as_deref(),
            Some("within the tail")
        );
    }
}
