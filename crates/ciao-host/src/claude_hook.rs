//! Ciao-owned Claude command-hook entry point.
//!
//! The command is deliberately silent and fail-open: when Ciao is unavailable or rejects an
//! observation, Claude's terminal session continues unchanged. Only whitelisted, bounded fields
//! are converted to the local Claude adapter protocol; transcript paths are never forwarded or
//! persisted.
//!
//! Tool arguments and results are forwarded as bounded previews, at parity with the Pi bridge.
//! They ride the end-to-end encrypted Iroh stream straight to the paired phone, are never
//! persisted on iOS, and never reach the control service or APNS — the same path that already
//! carries message text. The bound is on size, not on which keys exist, so an argument Ciao has
//! never heard of still reaches the reader that has to name the step.

use std::{
    env, fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::{Duration, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::time::timeout;

use crate::{
    agent_adapter::{AttachedHookRegister, WireTextDelta, WireTimelineEntry},
    agent_protocol::{
        MAX_LIVE_TEXT_DELTA_BYTES, MAX_TIMELINE_TEXT_BYTES, MAX_TOOL_INPUT_PREVIEW_BYTES,
        MAX_TOOL_RESULT_PREVIEW_BYTES, TimelineBody, ToolTimelineBody, Truncation, TurnState,
        classify_vendor_version, valid_opaque_id, valid_token,
    },
    claude_adapter::{CLAUDE_HOOK_PROTOCOL_VERSION, ClaudeHookEventFrame, PINNED_CLAUDE_VERSION},
    claude_integration::parse_claude_version_output,
    hook_common::{
        HOOK_DELIVERY_TIMEOUT, bounded_preview, bounded_text, deliver, keyed_digest, no_truncation,
        object, read_bounded_stdin, required_bool, required_string, required_u64, trace_outcome,
        unix_now, workspace_display,
    },
    storage::{CiaoPaths, atomic_write_private, validate_private_file},
};

/// Separates this vendor's digests from every other adapter's. Changing it renumbers every live
/// Claude entry, so it is frozen rather than tidied.
const CLAUDE_DIGEST_DOMAIN: &[u8] = b"ciao-claude-hook-v1\0";
const MAX_CLAUDE_HOOK_INPUT_BYTES: usize = 1024 * 1024;
/// This is a slice of Claude's budget, not ours to widen.
///
/// Claude kills the hook at the `"timeout": 2` seconds `claude_integration.rs` writes into
/// hooks.json, and `HOOK_DELIVERY_TIMEOUT` already claims 1500 ms of it. 250 ms is what is left.
/// Raising this to 2 s once — on the correct observation that a cold spawn needs longer — meant
/// the hook ran to Claude's ceiling instead of ours, and Claude replaced a silent miss with
/// "UserPromptSubmit hook timed out after 2s" in the user's terminal. Widen the hooks.json
/// timeout first, or do not widen this.
///
/// A cold spawn genuinely does exceed it: measured 500 ms through the mise node copy and 620 ms
/// through the mise shim, against 70 ms warm. That is answered by not treating a miss as fatal —
/// see `adapter_version_for_process` — rather than by spending time this hook does not have.
const HOOK_VERSION_TIMEOUT: Duration = Duration::from_millis(250);
const VERSION_CACHE_FILE_VERSION: u8 = 1;
const MAX_VERSION_CACHE_BYTES: u64 = 256;
const MAX_VERSION_CACHE_FILES: usize = 256;
const VERSION_CACHE_PREFIX: &str = ".claude-version-";
const VERSION_CACHE_SUFFIX: &str = ".json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VersionCache {
    v: u8,
    adapter_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HookRuntimeFacts {
    process_id: u32,
    process_nonce: String,
    adapter_version: String,
    environment_session_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HookDispatch {
    registration: AttachedHookRegister,
    event: ClaudeHookEventFrame,
    /// The turn edge this event establishes, delivered on its own connection (Spec 019).
    ///
    /// `None` for every event that only proves the process moved. A tool call, a display chunk,
    /// or a compaction says nothing about whether the turn is still open, and the registration
    /// riding alongside it cannot say either: `NormalizedRegistration::validate` refuses a
    /// working turn from a partially-observed session, which is how Spec 005 §1's "no
    /// registration path produces a `running` turn" is enforced.
    turn: Option<TurnState>,
}

/// Runs one command-hook delivery. Callers intentionally discard the result so a local Ciao
/// outage or unsupported payload never turns into a visible Claude hook error.
pub(crate) async fn run(paths: &CiaoPaths) -> Result<()> {
    let mut event = String::new();
    let result = observe(paths, &mut event).await;
    trace_outcome(paths, "hook.trace.log", &event, &result);
    result
}

async fn observe(paths: &CiaoPaths, event: &mut String) -> Result<()> {
    let body = read_bounded_stdin(MAX_CLAUDE_HOOK_INPUT_BYTES)?;
    let value: Value =
        serde_json::from_slice(&body).map_err(|_| anyhow!("invalid Claude hook input"))?;
    let session_id = required_string(object(&value)?, "session_id")?;
    valid_opaque_id(session_id).map_err(|_| anyhow!("Claude session ID is invalid"))?;
    let environment_session_id = env::var("CLAUDE_CODE_SESSION_ID")?;
    if environment_session_id != session_id
        || env::var("CLAUDE_CODE_CHILD_SESSION").as_deref() != Ok("1")
        || env::var("CLAUDECODE").as_deref() != Ok("1")
    {
        bail!("Claude hook environment did not authenticate the session");
    }
    if object(&value)?.contains_key("agent_id") {
        return Ok(());
    }
    let process_id = env::var("CLAUDE_PID")?.parse::<u32>()?;
    if process_id == 0 {
        bail!("Claude process ID is invalid");
    }
    let hook_event_name = required_string(object(&value)?, "hook_event_name")?;
    event.clear();
    event.push_str(hook_event_name);
    let adapter_version = adapter_version_for_process(
        paths,
        session_id,
        process_id,
        hook_event_name == "SessionStart",
    )
    .await?;
    let process_nonce = opaque_digest("process", &process_id.to_string());
    let facts = HookRuntimeFacts {
        process_id,
        process_nonce,
        adapter_version,
        environment_session_id,
    };
    let Some(dispatch) = map_hook_input(&value, &facts)? else {
        return Ok(());
    };
    let registration = serde_json::to_value(dispatch.registration)?;
    let event = serde_json::to_value(dispatch.event)?;
    let turn = dispatch
        .turn
        .map(|turn| {
            serde_json::to_value(ClaudeHookEventFrame::Turn {
                v: CLAUDE_HOOK_PROTOCOL_VERSION,
                turn,
            })
        })
        .transpose()?;
    timeout(HOOK_DELIVERY_TIMEOUT, async {
        deliver(paths, CLAUDE_HOOK_PROTOCOL_VERSION, &registration, &event).await?;
        // Second connection, after the event: one connection carries one event. The event goes
        // first so a turn that says "working" is never on screen before the prompt that caused
        // it, and so losing the second delivery costs a turn state rather than a message. The
        // two share this deadline, which is what makes that loss the one that happens.
        if let Some(turn) = turn {
            deliver(paths, CLAUDE_HOOK_PROTOCOL_VERSION, &registration, &turn).await?;
        }
        Ok(())
    })
    .await
    .map_err(|_| anyhow!("Ciao hook delivery timed out"))?
}

async fn adapter_version_for_process(
    paths: &CiaoPaths,
    session_id: &str,
    process_id: u32,
    force_refresh: bool,
) -> Result<String> {
    let cache_path = version_cache_path(paths, session_id, process_id);
    if !force_refresh && let Some(version) = read_version_cache(&cache_path)? {
        return Ok(version);
    }
    let probe = timeout(
        HOOK_VERSION_TIMEOUT,
        tokio::process::Command::new("claude")
            .arg("--version")
            .kill_on_drop(true)
            .output(),
    )
    .await;
    // A version is metadata; the event carrying it is the session existing at all. Reading it is
    // also the only part of this hook that spawns a process, so it is the part that loses when the
    // machine is busy — and it is forced at `SessionStart`, which is the busiest moment there is.
    // Failing the event there cost a whole tmux session: the forced refresh wrote no cache, so
    // every later event re-ran the same losing check, and Ciao never saw the session at all.
    //
    // So a miss falls back to the last version any session on this host read successfully. The
    // binary does not change under a running session, which is what makes that answer true rather
    // than merely available. Only a host that has never once read a version fails now.
    let last_known = last_known_version_path(paths);
    let version = match probe {
        Ok(Ok(output)) => parse_claude_version_output(&output)?,
        _ => match read_version_cache(&last_known).ok().flatten() {
            Some(version) => version,
            None => bail!("Claude version check timed out and no version has ever been read"),
        },
    };
    write_version_cache(paths, &cache_path, &version)?;
    write_version_cache(paths, &last_known, &version)?;
    Ok(version)
}

/// Host-wide, deliberately not keyed by session or process: its whole job is to answer for a
/// session that has never got an answer of its own.
fn last_known_version_path(paths: &CiaoPaths) -> PathBuf {
    let digest = keyed_digest(CLAUDE_DIGEST_DOMAIN, "version", "last-known");
    paths.run_dir.join(format!(
        "{VERSION_CACHE_PREFIX}{digest}{VERSION_CACHE_SUFFIX}"
    ))
}

fn version_cache_path(paths: &CiaoPaths, session_id: &str, process_id: u32) -> PathBuf {
    let digest = keyed_digest(
        CLAUDE_DIGEST_DOMAIN,
        "version",
        &format!("{session_id}\0{process_id}"),
    );
    paths.run_dir.join(format!(
        "{VERSION_CACHE_PREFIX}{digest}{VERSION_CACHE_SUFFIX}"
    ))
}

fn read_version_cache(path: &Path) -> Result<Option<String>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect Claude version cache"),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.len() == 0
        || metadata.len() > MAX_VERSION_CACHE_BYTES
    {
        bail!("Claude version cache is unsafe");
    }
    validate_private_file(path).context("validate Claude version cache")?;
    let bytes = fs::read(path).context("read Claude version cache")?;
    if bytes.len() as u64 > MAX_VERSION_CACHE_BYTES {
        bail!("Claude version cache exceeded its bound");
    }
    let cache: VersionCache = serde_json::from_slice(&bytes)?;
    if cache.v != VERSION_CACHE_FILE_VERSION || valid_token(&cache.adapter_version).is_err() {
        bail!("Claude version cache is invalid");
    }
    Ok(Some(cache.adapter_version))
}

fn write_version_cache(paths: &CiaoPaths, path: &Path, adapter_version: &str) -> Result<()> {
    valid_token(adapter_version).map_err(|_| anyhow!("Claude version token is invalid"))?;
    let metadata = match fs::symlink_metadata(&paths.run_dir) {
        Ok(metadata) => metadata,
        // When the Ciao daemon has never created its private runtime directory, observation is
        // unavailable anyway. Avoid creating daemon state from a vendor hook process.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspect Ciao runtime directory"),
    };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
    {
        bail!("Ciao runtime directory is unsafe");
    }
    prune_version_caches(&paths.run_dir, path)?;
    let encoded = serde_json::to_vec(&VersionCache {
        v: VERSION_CACHE_FILE_VERSION,
        adapter_version: adapter_version.into(),
    })?;
    if encoded.len() as u64 > MAX_VERSION_CACHE_BYTES {
        bail!("Claude version cache encoding exceeded its bound");
    }
    atomic_write_private(path, &encoded).context("write Claude version cache")
}

fn prune_version_caches(run_dir: &Path, preserved: &Path) -> Result<()> {
    let mut caches = Vec::new();
    for entry in fs::read_dir(run_dir).context("list Ciao runtime directory")? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !valid_version_cache_name(name) || entry.path() == preserved {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        {
            bail!("Claude version cache directory contains an unsafe owned name");
        }
        caches.push((metadata.modified().unwrap_or(UNIX_EPOCH), entry.path()));
    }
    caches.sort_by_key(|(modified, _)| *modified);
    let remove_count = caches
        .len()
        .saturating_sub(MAX_VERSION_CACHE_FILES.saturating_sub(1));
    for (_, path) in caches.into_iter().take(remove_count) {
        validate_private_file(&path).context("validate stale Claude version cache")?;
        fs::remove_file(path).context("remove stale Claude version cache")?;
    }
    Ok(())
}

fn valid_version_cache_name(name: &str) -> bool {
    let digest = name
        .strip_prefix(VERSION_CACHE_PREFIX)
        .and_then(|value| value.strip_suffix(VERSION_CACHE_SUFFIX));
    digest.is_some_and(|digest| {
        digest.len() == 32 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

/// Wrappers Claude puts around text it delivers through the prompt path itself: background-task
/// wake-ups, slash-command expansions, injected reminders, and `!` bash echoes. Observed in the
/// owner's own transcripts rather than guessed — `<task-notification>`, `<command-name>` and
/// `<local-command-caveat>` each appear dozens of times.
const SYNTHETIC_PROMPT_ENVELOPES: [&str; 8] = [
    "<task-notification>",
    "<system-reminder>",
    "<local-command-caveat>",
    "<local-command-stdout>",
    "<command-name>",
    "<command-message>",
    "<bash-input>",
    "<bash-stdout>",
];

/// Whether a `UserPromptSubmit` payload is machinery rather than something a person said.
///
/// The transcript records this properly — `promptSource: "system"` and `origin.kind`, which
/// [`claude_transcript::human_prompt`] already relies on — but the hook payload carries neither,
/// and the transcript line does not exist yet: this hook may still block the prompt, so nothing is
/// committed when it runs. The envelope is the only provenance available at this point.
///
/// ponytail: prefix match. A person who pastes one of these verbatim loses one timeline row and
/// nothing else — the prompt still reaches Claude untouched.
fn is_synthetic_prompt(prompt: &str) -> bool {
    let trimmed = prompt.trim_start();
    SYNTHETIC_PROMPT_ENVELOPES
        .iter()
        .any(|envelope| trimmed.starts_with(envelope))
}

fn map_hook_input(value: &Value, facts: &HookRuntimeFacts) -> Result<Option<HookDispatch>> {
    let object = object(value)?;
    let session_id = required_string(object, "session_id")?;
    valid_opaque_id(session_id).map_err(|_| anyhow!("Claude session ID is invalid"))?;
    if session_id != facts.environment_session_id {
        bail!("Claude hook session identity mismatched its environment");
    }
    // Subagent events share the parent session/process but are not the attached main-thread TUI.
    // Ignoring them is safer than interleaving timelines or claiming unsupported topology.
    if object.contains_key("agent_id") {
        return Ok(None);
    }
    let cwd = required_string(object, "cwd")?;
    let workspace_display = workspace_display(cwd);
    let event_name = required_string(object, "hook_event_name")?;
    let timestamp = unix_now();
    // Spec 017 Phase 2: a later 2.x minor is admitted as `ahead` — full observation with the
    // drift ledger counting anything unrecognized — instead of going dark until a Ciao release.
    // What still heartbeat-gates is a major bump, a build below the floor, or a prerelease:
    // versions whose payloads this build has no promise about at all.
    let mut turn = None;
    let event =
        if !classify_vendor_version(&facts.adapter_version, PINNED_CLAUDE_VERSION).admitted() {
            ClaudeHookEventFrame::Heartbeat {
                v: CLAUDE_HOOK_PROTOCOL_VERSION,
                // A gated version is refused, not novel; the gate already reports itself.
                unrecognized_event: None,
            }
        } else {
            match event_name {
                // `SessionStart` deliberately reports no turn, where Codex's reports `Idle`: it
                // also fires for `--resume` and `--continue`, into a conversation whose state
                // Ciao never watched. `Idle` there would be a claim rather than an observation.
                "SessionStart" | "PreCompact" | "PostCompact" => ClaudeHookEventFrame::Heartbeat {
                    v: CLAUDE_HOOK_PROTOCOL_VERSION,
                    unrecognized_event: None,
                },
                // The turn closes. Claude repeats the opening `prompt_id` here — verified
                // against a real 2.1.222 payload — so the close names the exact run it closes
                // rather than an anonymous one.
                "Stop" => {
                    turn = Some(TurnState::Completed {
                        run_id: object
                            .get("prompt_id")
                            .and_then(Value::as_str)
                            .map(run_id)
                            .filter(|run_id| valid_opaque_id(run_id).is_ok()),
                    });
                    ClaudeHookEventFrame::Heartbeat {
                        v: CLAUDE_HOOK_PROTOCOL_VERSION,
                        unrecognized_event: None,
                    }
                }
                "UserPromptSubmit" => {
                    let prompt = required_string(object, "prompt")?;
                    if is_synthetic_prompt(prompt) {
                        // Machinery, not a turn. It still proves the session is alive, and a dropped
                        // `UserPromptSubmit` never comes back, so this reports liveness rather than
                        // returning `None` and losing the registration with it.
                        ClaudeHookEventFrame::Heartbeat {
                            v: CLAUDE_HOOK_PROTOCOL_VERSION,
                            unrecognized_event: None,
                        }
                    } else {
                        let prompt_id = required_string(object, "prompt_id")?;
                        // The turn opens. This is the one hook that proves a person asked for
                        // work, which is the only thing Ciao is willing to call the start of one.
                        turn = Some(TurnState::Running {
                            run_id: run_id(prompt_id),
                            activity: "responding".into(),
                        });
                        let (text, truncation) = bounded_text(prompt, MAX_TIMELINE_TEXT_BYTES);
                        ClaudeHookEventFrame::UpsertEntry {
                            v: CLAUDE_HOOK_PROTOCOL_VERSION,
                            entry: WireTimelineEntry {
                                source_id: opaque_digest("prompt", prompt_id),
                                source_revision: 1,
                                timestamp,
                                state: "complete".into(),
                                kind: "user_message".into(),
                                body: TimelineBody::Text { text },
                                truncation,
                            },
                        }
                    }
                }
                "MessageDisplay" => {
                    let message_id = required_string(object, "message_id")?;
                    let index = required_u64(object, "index")?;
                    let final_chunk = required_bool(object, "final")?;
                    let (delta, truncation) =
                        bounded_text(required_string(object, "delta")?, MAX_LIVE_TEXT_DELTA_BYTES);
                    ClaudeHookEventFrame::AppendText {
                        v: CLAUDE_HOOK_PROTOCOL_VERSION,
                        delta: WireTextDelta {
                            source_id: opaque_digest("message", message_id),
                            source_revision: index
                                .checked_add(1)
                                .ok_or_else(|| anyhow!("Claude display index overflowed"))?,
                            timestamp,
                            kind: "assistant_message".into(),
                            delta,
                            final_chunk,
                            truncation,
                        },
                    }
                }
                // The one hook that says "needs you" (ADR 005). Claude Code names its own reason in
                // `notification_type` — `permission_prompt` and `idle_prompt` are the two this
                // product exists to deliver — so the kind is forwarded and the vendor `message` is
                // not: it is a constant per kind ("Claude needs your permission"), and the copy a
                // notification should carry names the workspace, which registration already sends.
                // Notifications raised by MCP servers carry no type at all, hence the named default.
                "Notification" => {
                    let kind = match object.get("notification_type") {
                        None => "unspecified",
                        Some(value) => value
                            .as_str()
                            .filter(|kind| valid_token(kind).is_ok())
                            .ok_or_else(|| anyhow!("Claude notification type is invalid"))?,
                    };
                    ClaudeHookEventFrame::Notification {
                        v: CLAUDE_HOOK_PROTOCOL_VERSION,
                        kind: kind.into(),
                    }
                }
                "PreToolUse" => tool_event(object, timestamp, "streaming", "running", 1)?,
                "PostToolUse" => tool_event(object, timestamp, "complete", "completed", 2)?,
                "PostToolUseFailure" => tool_event(object, timestamp, "failed", "failed", 2)?,
                "StopFailure" => {
                    let correlation = object
                        .get("prompt_id")
                        .and_then(Value::as_str)
                        .unwrap_or(session_id);
                    ClaudeHookEventFrame::UpsertEntry {
                        v: CLAUDE_HOOK_PROTOCOL_VERSION,
                        entry: WireTimelineEntry {
                            source_id: opaque_digest("stop_failure", correlation),
                            source_revision: 1,
                            timestamp,
                            state: "failed".into(),
                            kind: "unsupported".into(),
                            body: TimelineBody::Unsupported {
                                reason_code: "claude_stop_failure".into(),
                            },
                            truncation: no_truncation(),
                        },
                    }
                }
                "SessionEnd" => ClaudeHookEventFrame::SessionEnd {
                    v: CLAUDE_HOOK_PROTOCOL_VERSION,
                },
                // An event name outside this build's vocabulary — the plugin subscribes to events
                // by name, so this fires only when the vendor renames or re-times something, which
                // is exactly what the drift ledger exists to catch (Spec 017 §4.2). The heartbeat
                // it already degraded to carries the name; the daemon tallies it on decode.
                _ => ClaudeHookEventFrame::Heartbeat {
                    v: CLAUDE_HOOK_PROTOCOL_VERSION,
                    unrecognized_event: Some(crate::drift::sanitize_name(event_name)),
                },
            }
        };
    Ok(Some(HookDispatch {
        registration: AttachedHookRegister {
            v: CLAUDE_HOOK_PROTOCOL_VERSION,
            message_type: "register".into(),
            adapter: "claude".into(),
            adapter_version: facts.adapter_version.clone(),
            mode: "tui_hook".into(),
            session_id: session_id.into(),
            process_nonce: facts.process_nonce.clone(),
            process_id: facts.process_id,
            workspace_display,
            // The working directory, and only that. `transcript_path` stays out: it points
            // at the whole conversation on disk and nothing here needs it. This crosses a
            // same-user local socket to the daemon, which already stores an absolute path
            // for every managed session, and is never copied into a descriptor.
            workspace_path: cwd.to_owned(),
        },
        event,
        turn,
    }))
}

/// The Ciao run ID for a Claude turn, derived from the vendor's `prompt_id`.
///
/// `UserPromptSubmit` and the `Stop` that closes it carry the same one, so both edges of a turn
/// name the same run without the host holding any correlation state. The vendor's ID never
/// leaves this process.
fn run_id(prompt_id: &str) -> String {
    // `opaque_digest` already namespaces what it returns — prefixing it again here produced
    // `claude.turn.claude.turn.<digest>`, which the live walk printed into the daemon log.
    // Harmless, since a run ID is opaque and only ever compared for equality, and both edges
    // carried the same doubled value. Still wrong, and a human reads that line.
    opaque_digest("turn", prompt_id)
}

fn tool_event(
    object: &Map<String, Value>,
    timestamp: u64,
    state: &str,
    status: &str,
    source_revision: u64,
) -> Result<ClaudeHookEventFrame> {
    let tool_name = required_string(object, "tool_name")?;
    let tool_use_id = required_string(object, "tool_use_id")?;
    let safe_name = if valid_token(tool_name).is_ok() {
        tool_name.into()
    } else {
        "unknown_tool".into()
    };
    let (input_preview, input_clipped) =
        bounded_preview(object.get("tool_input"), MAX_TOOL_INPUT_PREVIEW_BYTES);
    let (result_preview, result_clipped) =
        bounded_preview(object.get("tool_response"), MAX_TOOL_RESULT_PREVIEW_BYTES);
    let truncation = if input_clipped || result_clipped {
        Truncation {
            truncated: true,
            reason_code: Some("preview_bounded".into()),
            original_bytes: None,
        }
    } else {
        no_truncation()
    };
    Ok(ClaudeHookEventFrame::UpsertEntry {
        v: CLAUDE_HOOK_PROTOCOL_VERSION,
        entry: WireTimelineEntry {
            source_id: opaque_digest("tool", tool_use_id),
            source_revision,
            timestamp,
            state: state.into(),
            // The canonical kind is "tool", which is what Pi's bridge emits and what iOS
            // collapses into a work disclosure. "tool_use" is Claude's own field name and
            // is not in the vocabulary, so it decoded to `unsupported` and every call got
            // its own uncollapsible card.
            kind: "tool".into(),
            body: TimelineBody::Tool {
                tool: ToolTimelineBody {
                    name: safe_name,
                    status: status.into(),
                    input_preview,
                    result_preview,
                },
            },
            truncation,
        },
    })
}

fn opaque_digest(namespace: &str, value: &str) -> String {
    format!(
        "claude.{namespace}.{}",
        keyed_digest(CLAUDE_DIGEST_DOMAIN, namespace, value)
    )
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use serde_json::json;
    use tempfile::tempdir;

    use super::*;
    use crate::hook_common::GENEROUS_PREVIEW_STRING_BYTES;

    fn facts() -> HookRuntimeFacts {
        HookRuntimeFacts {
            process_id: 42,
            process_nonce: "0123456789abcdef0123456789abcdef".into(),
            adapter_version: PINNED_CLAUDE_VERSION.into(),
            environment_session_id: "fixture-session".into(),
        }
    }

    fn common(event: &str) -> Value {
        json!({
            "session_id": "fixture-session",
            "transcript_path": "/private/synthetic/transcript.jsonl",
            "cwd": "/private/synthetic/Fixture workspace",
            "hook_event_name": event
        })
    }

    #[test]
    fn user_and_display_events_forward_only_the_working_directory() {
        let mut user = common("UserPromptSubmit");
        user["prompt_id"] = json!("fixture-prompt-id");
        user["prompt"] = json!("Synthetic prompt.");
        let mapped = map_hook_input(&user, &facts()).unwrap().unwrap();
        let registration = serde_json::to_string(&mapped.registration).unwrap();
        // The transcript path is the whole conversation on disk and is never forwarded.
        assert!(!registration.contains("transcript.jsonl"));
        assert_eq!(mapped.registration.workspace_display, "Fixture workspace");
        // The working directory is forwarded deliberately: promotion has to launch the
        // managed worker somewhere, and a basename cannot say where.
        assert_eq!(
            mapped.registration.workspace_path,
            "/private/synthetic/Fixture workspace"
        );
        assert!(
            !mapped
                .registration
                .process_nonce
                .contains("fixture-session")
        );
        let ClaudeHookEventFrame::UpsertEntry { entry, .. } = mapped.event else {
            panic!("expected user entry");
        };
        assert!(entry.source_id.starts_with("claude.prompt."));
        assert!(!entry.source_id.contains("fixture-prompt-id"));
        assert_eq!(
            entry.body,
            TimelineBody::Text {
                text: "Synthetic prompt.".into()
            }
        );

        let mut display = common("MessageDisplay");
        display["message_id"] = json!("fixture-message-id");
        display["index"] = json!(0);
        display["final"] = json!(true);
        display["delta"] = json!("Synthetic response.");
        let mapped = map_hook_input(&display, &facts()).unwrap().unwrap();
        let ClaudeHookEventFrame::AppendText { delta, .. } = mapped.event else {
            panic!("expected display delta");
        };
        assert_eq!(delta.source_revision, 1);
        assert!(delta.final_chunk);
        assert!(!delta.source_id.contains("fixture-message-id"));
    }

    /// A hook event name outside this build's vocabulary degrades to the same heartbeat it
    /// always did, but now carries the vendor's name for it so the daemon can tally the drift
    /// (Spec 017 §4.2). The name is sanitized before it rides: hostile bytes become `invalid`.
    #[test]
    fn an_unknown_event_name_rides_the_heartbeat_as_drift() {
        let mapped = map_hook_input(&common("EventFromAFutureClaude"), &facts())
            .unwrap()
            .unwrap();
        assert_eq!(
            mapped.event,
            ClaudeHookEventFrame::Heartbeat {
                v: CLAUDE_HOOK_PROTOCOL_VERSION,
                unrecognized_event: Some("EventFromAFutureClaude".into()),
            }
        );

        let mapped = map_hook_input(&common("weird event\nname"), &facts())
            .unwrap()
            .unwrap();
        assert_eq!(
            mapped.event,
            ClaudeHookEventFrame::Heartbeat {
                v: CLAUDE_HOOK_PROTOCOL_VERSION,
                unrecognized_event: Some("invalid".into()),
            },
            "a name that fails vendor-vocabulary grammar is never repeated verbatim"
        );
    }

    /// Claude delivers background-task wake-ups and slash-command expansions through the same hook
    /// a person's typing uses. Left unfiltered they became `user_message` entries, which iOS draws
    /// in the prompt bubble — the timeline said the owner had said things the owner never said.
    #[test]
    fn machinery_delivered_as_a_prompt_makes_no_timeline_entry() {
        for prompt in [
            "<task-notification>\n<task-id>b22lymfqd</task-id>\n</task-notification>",
            "<command-name>/clear</command-name>",
            "<local-command-caveat>ignore me",
            "<local-command-stdout>output",
            "<system-reminder>remember something",
            "<bash-input>ls",
            "  \n<task-notification>leading whitespace still counts",
        ] {
            let mut user = common("UserPromptSubmit");
            user["prompt_id"] = json!("fixture-prompt-id");
            user["prompt"] = json!(prompt);
            let mapped = map_hook_input(&user, &facts()).unwrap().unwrap();
            assert!(
                matches!(mapped.event, ClaudeHookEventFrame::Heartbeat { .. }),
                "expected a heartbeat rather than a turn for {prompt:?}"
            );
        }
    }

    /// The session still has to stay registered: a dropped `UserPromptSubmit` never comes back, so
    /// filtering the entry must not cost the registration travelling with it.
    #[test]
    fn a_filtered_prompt_still_registers_the_session() {
        let mut user = common("UserPromptSubmit");
        user["prompt_id"] = json!("fixture-prompt-id");
        user["prompt"] = json!("<task-notification>done</task-notification>");
        let mapped = map_hook_input(&user, &facts()).unwrap().unwrap();
        assert_eq!(mapped.registration.workspace_display, "Fixture workspace");
    }

    /// The one thing this must never do is eat a real prompt that merely mentions the machinery,
    /// or one that opens with ordinary angle-bracketed text.
    #[test]
    fn ordinary_prompts_are_untouched() {
        for prompt in [
            "I saw a task-notification sent on my behalf, what is that?",
            "explain <task-notification> to me",
            "<div>is not machinery</div>",
            "</task-notification> unbalanced",
        ] {
            let mut user = common("UserPromptSubmit");
            user["prompt_id"] = json!("fixture-prompt-id");
            user["prompt"] = json!(prompt);
            let mapped = map_hook_input(&user, &facts()).unwrap().unwrap();
            let ClaudeHookEventFrame::UpsertEntry { entry, .. } = mapped.event else {
                panic!("expected a user entry for {prompt:?}");
            };
            assert_eq!(entry.kind, "user_message");
        }
    }

    #[test]
    fn tool_arguments_are_forwarded_bounded_while_vendor_identity_stays_local() {
        let command = "rg --files-with-matches TODO";
        let mut event = common("PreToolUse");
        event["prompt_id"] = json!("fixture-prompt-id");
        event["tool_name"] = json!("Bash");
        event["tool_use_id"] = json!("fixture-tool-use-id");
        event["tool_input"] = json!({"command": command});
        let mapped = map_hook_input(&event, &facts()).unwrap().unwrap();
        let encoded = serde_json::to_string(&mapped.event).unwrap();
        // The argument is what names the step on the phone, so it must survive.
        assert!(encoded.contains(command));
        assert!(encoded.contains("running"));
        assert!(encoded.contains("Bash"));
        // The vendor's own identifier still never leaves: the source ID is a digest of it.
        assert!(!encoded.contains("fixture-tool-use-id"));
    }

    #[test]
    fn an_oversized_argument_is_capped_but_still_parses_as_json() {
        let mut event = common("PreToolUse");
        event["tool_name"] = json!("Write");
        event["tool_use_id"] = json!("fixture-tool-use-id");
        event["tool_input"] = json!({
            "file_path": "/tmp/generated.swift",
            "content": "x".repeat(GENEROUS_PREVIEW_STRING_BYTES * 4),
        });
        let mapped = map_hook_input(&event, &facts()).unwrap().unwrap();
        let ClaudeHookEventFrame::UpsertEntry { entry, .. } = mapped.event else {
            panic!("expected a tool entry");
        };
        let TimelineBody::Tool { tool } = entry.body else {
            panic!("expected a tool body");
        };
        let preview = tool.input_preview.expect("a capped argument is still sent");
        // Truncating the serialized text instead would leave a document that does not parse,
        // and the reader would fall back to the bare tool name.
        let parsed: Value = serde_json::from_str(&preview).expect("the preview parses");
        assert_eq!(parsed["file_path"], json!("/tmp/generated.swift"));
        assert!(parsed["content"].as_str().unwrap().len() <= GENEROUS_PREVIEW_STRING_BYTES);
        assert!(entry.truncation.truncated);
        assert_eq!(
            entry.truncation.reason_code.as_deref(),
            Some("preview_bounded")
        );
    }

    #[test]
    fn large_vendor_tool_results_are_discarded_before_the_local_frame() {
        let canary = "CIAO_PRIVATE_LARGE_TOOL_RESULT".repeat(4096);
        let mut event = common("PostToolUse");
        event["tool_name"] = json!("Bash");
        event["tool_use_id"] = json!("fixture-tool-use-id");
        event["tool_input"] = json!({"command": "synthetic"});
        event["tool_response"] = json!({"content": canary});
        let vendor_bytes = serde_json::to_vec(&event).unwrap();
        assert!(vendor_bytes.len() > crate::agent_protocol::MAX_AGENT_FRAME_BYTES);
        assert!(vendor_bytes.len() < MAX_CLAUDE_HOOK_INPUT_BYTES);
        let parsed: Value = serde_json::from_slice(&vendor_bytes).unwrap();
        let mapped = map_hook_input(&parsed, &facts()).unwrap().unwrap();
        let local_bytes = serde_json::to_vec(&mapped.event).unwrap();
        // Previews are forwarded now, so the guarantee is the bound rather than absence: a
        // vendor result far larger than one frame must never produce a frame that large.
        assert!(local_bytes.len() < crate::agent_protocol::MAX_AGENT_FRAME_BYTES);
        let rendered = String::from_utf8_lossy(&local_bytes);
        assert!(
            rendered.matches("CIAO_PRIVATE_LARGE_TOOL_RESULT").count() * canary_unit_len()
                <= GENEROUS_PREVIEW_STRING_BYTES,
            "a result is capped to one bounded string, not forwarded whole"
        );
    }

    fn canary_unit_len() -> usize {
        "CIAO_PRIVATE_LARGE_TOOL_RESULT".len()
    }

    #[test]
    fn notifications_carry_the_vendor_reason_and_nothing_else() {
        // Both payloads are verbatim captures from Claude Code 2.1.220: the two reasons are
        // distinguishable, so "needs permission" and "waiting for you" can read differently.
        for (notification_type, message) in [
            ("permission_prompt", "Claude needs your permission"),
            ("idle_prompt", "Claude is waiting for your input"),
        ] {
            let mut event = common("Notification");
            event["prompt_id"] = json!("fixture-prompt-id");
            event["message"] = json!(message);
            event["notification_type"] = json!(notification_type);
            let mapped = map_hook_input(&event, &facts()).unwrap().unwrap();
            assert_eq!(
                mapped.event,
                ClaudeHookEventFrame::Notification {
                    v: CLAUDE_HOOK_PROTOCOL_VERSION,
                    kind: notification_type.into(),
                }
            );
            // The vendor string is a constant per reason and names no workspace, so it is not
            // forwarded; the reason is what a notification is built from.
            assert!(
                !serde_json::to_string(&mapped.event)
                    .unwrap()
                    .contains(message)
            );
        }

        // Claude Code raises MCP-server notifications with no reason at all.
        let mut untyped = common("Notification");
        untyped["message"] = json!("MCP server \"fixture\" needs authentication");
        assert_eq!(
            map_hook_input(&untyped, &facts()).unwrap().unwrap().event,
            ClaudeHookEventFrame::Notification {
                v: CLAUDE_HOOK_PROTOCOL_VERSION,
                kind: "unspecified".into(),
            }
        );
    }

    /// Spec 019. The two edges, and the correlation that ties them together: Claude repeats the
    /// opening `prompt_id` on `Stop`, verified against a real 2.1.222 payload, so a close names
    /// the run it closes without the host holding any state between the two.
    #[test]
    fn a_prompt_opens_a_turn_and_stop_closes_the_same_one() {
        let mut prompt = common("UserPromptSubmit");
        prompt["prompt_id"] = json!("fixture-prompt-id");
        prompt["prompt"] = json!("Synthetic prompt.");
        let opened = map_hook_input(&prompt, &facts()).unwrap().unwrap();
        let Some(TurnState::Running { run_id, activity }) = opened.turn.clone() else {
            panic!("a real prompt opens a turn");
        };
        assert_eq!(activity, "responding");
        // `starts_with` alone passed happily while the namespace was applied twice and the live
        // walk logged `claude.turn.claude.turn.<digest>`. Pin the whole shape instead: one
        // prefix, then the digest and nothing else.
        assert_eq!(run_id.matches("claude.turn.").count(), 1);
        let digest = run_id
            .strip_prefix("claude.turn.")
            .expect("namespaced run ID");
        assert!(!digest.is_empty() && digest.chars().all(|c| c.is_ascii_hexdigit()));
        // The vendor's own ID never leaves this process, in either direction.
        assert!(!run_id.contains("fixture-prompt-id"));
        // The turn rides its own frame, never the registration: a registration that stated a
        // working turn would be refused by the daemon and the connection closed mid-handshake,
        // taking the prompt with it. Spec 005 §1.
        assert!(matches!(
            opened.event,
            ClaudeHookEventFrame::UpsertEntry { .. }
        ));

        let mut stop = common("Stop");
        stop["prompt_id"] = json!("fixture-prompt-id");
        stop["stop_hook_active"] = json!(false);
        let closed = map_hook_input(&stop, &facts()).unwrap().unwrap();
        assert_eq!(
            closed.turn,
            Some(TurnState::Completed {
                run_id: Some(run_id)
            }),
            "the close names the run the prompt opened"
        );

        // A `Stop` that arrives without one still closes the turn. `run_id: None` is the legal
        // spelling for a close Ciao cannot name, and refusing here would strand the claim.
        let closed = map_hook_input(&common("Stop"), &facts()).unwrap().unwrap();
        assert_eq!(closed.turn, Some(TurnState::Completed { run_id: None }));
    }

    /// The other ten subscribed events say nothing about the turn, and this is the fence that
    /// keeps it that way. A tool call proves the process moved, not that the turn is still open;
    /// an eleventh event added without deciding its turn semantics fails here rather than
    /// shipping a guess.
    #[test]
    fn only_a_prompt_and_a_stop_may_state_a_turn() {
        let mut display = common("MessageDisplay");
        display["message_id"] = json!("fixture-message-id");
        display["index"] = json!(0);
        display["final"] = json!(true);
        display["delta"] = json!("Synthetic response.");

        let mut tool = common("PreToolUse");
        tool["tool_name"] = json!("Read");
        tool["tool_use_id"] = json!("fixture-tool-id");

        let mut post = tool.clone();
        post["hook_event_name"] = json!("PostToolUse");
        let mut failure = tool.clone();
        failure["hook_event_name"] = json!("PostToolUseFailure");

        let mut synthetic = common("UserPromptSubmit");
        synthetic["prompt_id"] = json!("fixture-prompt-id");
        synthetic["prompt"] = json!("<command-name>/model</command-name>");

        let mut notification = common("Notification");
        notification["notification_type"] = json!("permission_prompt");

        for silent in [
            common("SessionStart"),
            common("PreCompact"),
            common("PostCompact"),
            common("StopFailure"),
            common("SessionEnd"),
            notification,
            display,
            tool,
            post,
            failure,
            // Machinery the person did not type. It proves the session is alive and nothing more.
            synthetic,
        ] {
            let name = silent["hook_event_name"].as_str().unwrap().to_owned();
            assert_eq!(
                map_hook_input(&silent, &facts()).unwrap().unwrap().turn,
                None,
                "{name} must not state a turn"
            );
        }
    }

    /// A gated build observes nothing, and that has to include the turn: a payload whose shape
    /// this binary has no promise about cannot be read as a turn boundary either.
    #[test]
    fn an_unsupported_build_reports_no_turn() {
        let mut prompt = common("UserPromptSubmit");
        prompt["prompt_id"] = json!("fixture-prompt-id");
        prompt["prompt"] = json!("Synthetic prompt.");
        let mut major = facts();
        major.adapter_version = "3.0.0".into();
        assert_eq!(map_hook_input(&prompt, &major).unwrap().unwrap().turn, None);
        assert_eq!(
            map_hook_input(&common("Stop"), &major)
                .unwrap()
                .unwrap()
                .turn,
            None
        );
    }

    /// The bytes this hook writes are the bytes the daemon reads, across a process boundary and
    /// a socket, with nothing in between to notice a disagreement.
    ///
    /// This is the exact bug class Spec 019 came from: the mapper grew a `Stop` arm, the plugin
    /// never subscribed the event, and for months the silence read as "Claude has no turn
    /// boundary". A producer and a consumer that drift apart here fail the same way — quietly —
    /// so the round trip is asserted rather than assumed from two hand-written fixtures.
    #[test]
    fn the_turn_frames_this_hook_writes_are_the_ones_the_daemon_decodes() {
        use crate::{
            agent_adapter::{AttachedAgentAdapter, NormalizedAdapterEvent},
            claude_adapter::ClaudeAttachedAdapter,
        };

        let mut prompt = common("UserPromptSubmit");
        prompt["prompt_id"] = json!("fixture-prompt-id");
        prompt["prompt"] = json!("Synthetic prompt.");
        let mut stop = common("Stop");
        stop["prompt_id"] = json!("fixture-prompt-id");

        for payload in [prompt, stop] {
            let name = payload["hook_event_name"].as_str().unwrap().to_owned();
            let turn = map_hook_input(&payload, &facts())
                .unwrap()
                .unwrap()
                .turn
                .unwrap_or_else(|| panic!("{name} states a turn"));
            let wire = serde_json::to_vec(&ClaudeHookEventFrame::Turn {
                v: CLAUDE_HOOK_PROTOCOL_VERSION,
                turn: turn.clone(),
            })
            .unwrap();
            assert_eq!(
                ClaudeAttachedAdapter.decode_event(&wire).unwrap(),
                NormalizedAdapterEvent::Turn(turn),
                "{name}'s turn frame must survive its own serialization"
            );
        }
    }

    #[test]
    fn malformed_notifications_are_refused_like_every_other_event() {
        for notification_type in [json!(7), json!("has spaces"), json!(""), json!(null)] {
            let mut event = common("Notification");
            event["notification_type"] = notification_type;
            assert!(map_hook_input(&event, &facts()).is_err());
        }
        let mut no_workspace = common("Notification");
        no_workspace["cwd"] = json!("");
        assert!(map_hook_input(&no_workspace, &facts()).is_err());

        // A notification from a subagent is not the attached main-thread session.
        let mut subagent = common("Notification");
        subagent["agent_id"] = json!("fixture-subagent");
        assert!(map_hook_input(&subagent, &facts()).unwrap().is_none());
    }

    /// Spec 017 Phase 2, both halves of the admission line. A later 2.x minor used to be this
    /// test's *refused* case; it now observes in full — that flip is the phase's whole point,
    /// made deliberately here rather than discovered as a regression. A major bump still says
    /// nothing but a heartbeat: no payload promise exists across a major.
    #[test]
    fn a_later_minor_observes_in_full_and_a_major_emits_only_a_heartbeat() {
        let mut display = common("MessageDisplay");
        display["message_id"] = json!("fixture-message-id");
        display["index"] = json!(0);
        display["final"] = json!(true);
        display["delta"] = json!("Synthetic response.");

        let mut ahead = facts();
        ahead.adapter_version = "2.2.0".into();
        let mapped = map_hook_input(&display, &ahead).unwrap().unwrap();
        assert_eq!(mapped.registration.adapter_version, "2.2.0");
        assert!(
            matches!(mapped.event, ClaudeHookEventFrame::AppendText { .. }),
            "a 2.x minor is ahead, not dark: the display event must map, not degrade"
        );

        let mut major = facts();
        major.adapter_version = "3.0.0".into();
        let mapped = map_hook_input(&display, &major).unwrap().unwrap();
        assert_eq!(mapped.registration.adapter_version, "3.0.0");
        assert_eq!(
            mapped.event,
            ClaudeHookEventFrame::Heartbeat {
                v: CLAUDE_HOOK_PROTOCOL_VERSION,
                unrecognized_event: None,
            },
            "a major is gated, and a gated version is refused, not novel"
        );
    }

    #[test]
    fn subagent_and_mismatched_session_events_are_not_attached() {
        let mut subagent = common("SessionStart");
        subagent["agent_id"] = json!("fixture-subagent");
        assert!(map_hook_input(&subagent, &facts()).unwrap().is_none());

        let mut mismatch = facts();
        mismatch.environment_session_id = "other-session".into();
        assert!(map_hook_input(&common("SessionStart"), &mismatch).is_err());
    }

    #[test]
    fn text_bounds_preserve_utf8_and_report_original_size() {
        let value = "🦀".repeat((MAX_LIVE_TEXT_DELTA_BYTES / 4) + 2);
        let (bounded, truncation) = bounded_text(&value, MAX_LIVE_TEXT_DELTA_BYTES - 1);
        assert!(bounded.is_char_boundary(bounded.len()));
        assert!(bounded.len() < MAX_LIVE_TEXT_DELTA_BYTES);
        assert!(truncation.truncated);
        assert_eq!(truncation.original_bytes, Some(value.len() as u64));
    }

    #[test]
    fn version_cache_is_private_opaque_and_disk_bounded() {
        let temporary = tempdir().unwrap();
        let paths = CiaoPaths::for_home(temporary.path());
        fs::create_dir_all(&paths.run_dir).unwrap();
        fs::set_permissions(&paths.run_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let path = version_cache_path(&paths, "fixture-private-session", 42);
        assert!(!path.to_string_lossy().contains("fixture-private-session"));

        let encoded = serde_json::to_vec(&VersionCache {
            v: VERSION_CACHE_FILE_VERSION,
            adapter_version: PINNED_CLAUDE_VERSION.into(),
        })
        .unwrap();
        for index in 0..(MAX_VERSION_CACHE_FILES + 3) {
            let stale = paths.run_dir.join(format!(
                "{VERSION_CACHE_PREFIX}{index:032x}{VERSION_CACHE_SUFFIX}"
            ));
            fs::write(&stale, &encoded).unwrap();
            fs::set_permissions(&stale, fs::Permissions::from_mode(0o600)).unwrap();
        }
        write_version_cache(&paths, &path, PINNED_CLAUDE_VERSION).unwrap();
        assert_eq!(
            read_version_cache(&path).unwrap().as_deref(),
            Some(PINNED_CLAUDE_VERSION)
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let count = fs::read_dir(&paths.run_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(valid_version_cache_name)
            })
            .count();
        assert_eq!(count, MAX_VERSION_CACHE_FILES);
    }

    #[test]
    fn process_nonce_fingerprint_is_stable_and_namespaced() {
        let first = opaque_digest("process", "session\0pid\0start");
        let second = opaque_digest("process", "session\0pid\0start");
        assert_eq!(first, second);
        assert_ne!(first, opaque_digest("process", "session\0pid\0other"));
        assert_ne!(first, opaque_digest("prompt", "session\0pid\0start"));
    }
}
