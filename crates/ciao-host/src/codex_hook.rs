//! Ciao-owned Codex command-hook entry point (Spec 012 §5).
//!
//! The command is deliberately silent and fail-open: when Ciao is unavailable or rejects an
//! observation, the Codex terminal session continues unchanged. Only whitelisted, bounded fields
//! are converted to the local Codex adapter protocol; `transcript_path` is never forwarded or
//! persisted.
//!
//! Two things differ from the Claude hook, and both come from the vendor rather than from taste:
//!
//! - **Codex exports no session identity in the hook environment.** Claude's hook cross-checks
//!   `CLAUDE_CODE_SESSION_ID`/`CLAUDE_PID` against its payload; there is nothing to check here,
//!   so identity is the process tree, resolved below and re-proved by `agent_bridge`.
//! - **There is no streaming display hook.** `Stop` carries `last_assistant_message` whole, so a
//!   turn's answer appears when the turn ends rather than as it is written.

use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value};
use tokio::time::timeout;

use crate::{
    agent_adapter::{AttachedHookRegister, WireTimelineEntry},
    agent_protocol::{
        MAX_TIMELINE_TEXT_BYTES, MAX_TOOL_INPUT_PREVIEW_BYTES, MAX_TOOL_RESULT_PREVIEW_BYTES,
        TimelineBody, ToolTimelineBody, Truncation, TurnState, classify_vendor_version,
        valid_opaque_id, valid_token,
    },
    codex_adapter::{
        CODEX_DIGEST_DOMAIN, CODEX_HOOK_PROTOCOL_VERSION, CodexHookEventFrame,
        PINNED_CODEX_VERSION, codex_run_id,
    },
    hook_common::{
        HOOK_DELIVERY_TIMEOUT, bounded_preview, bounded_text, deliver, keyed_digest, no_truncation,
        object, read_bounded_stdin, required_string, trace_outcome, unix_now, workspace_display,
    },
    process::{command as process_command, parent as process_parent},
    storage::CiaoPaths,
};

const MAX_CODEX_HOOK_INPUT_BYTES: usize = 1024 * 1024;
/// `codex --version` is a Rust binary behind a thin wrapper and answers in well under 150ms on
/// the grounded machine, so it is asked every time rather than cached — the Claude hook's per-process
/// version cache exists because its `--version` is a slow JavaScript bundle.
const HOOK_VERSION_TIMEOUT: Duration = Duration::from_millis(400);
/// How far up the process tree to look for the Codex process. The hook's own parent is Codex on
/// the grounded machine; the allowance covers a vendor that later interposes a shell.
const MAX_CODEX_ANCESTRY: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
struct HookRuntimeFacts {
    process_id: u32,
    process_nonce: String,
    adapter_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HookDispatch {
    registration: AttachedHookRegister,
    event: CodexHookEventFrame,
    /// The turn this event establishes, delivered on its own connection.
    ///
    /// It cannot ride on the registration: `NormalizedRegistration::validate` refuses a working
    /// turn from a partially-observed session, which is how Spec 005 §1's "no registration path
    /// produces a `running` turn" is enforced. A registration that tried was rejected outright
    /// and the connection closed, so the prompt never reached the timeline while the answer did.
    turn: Option<TurnState>,
}

pub(crate) async fn run(paths: &CiaoPaths) -> Result<()> {
    // Read-only: a hook consults the carry verdict the daemon (or a CLI check) wrote, and
    // never runs the verification itself — a one-shot delivery has no budget for it.
    crate::codex_carry::bind(paths, false);
    let mut event = String::new();
    let result = observe(paths, &mut event).await;
    trace_outcome(paths, "codex-hook.trace.log", &event, &result);
    result
}

async fn observe(paths: &CiaoPaths, event: &mut String) -> Result<()> {
    let body = read_bounded_stdin(MAX_CODEX_HOOK_INPUT_BYTES)?;
    let value: Value =
        serde_json::from_slice(&body).map_err(|_| anyhow!("invalid Codex hook input"))?;
    let session_id = required_string(object(&value)?, "session_id")?;
    valid_opaque_id(session_id).map_err(|_| anyhow!("Codex thread ID is invalid"))?;
    let hook_event_name = required_string(object(&value)?, "hook_event_name")?;
    event.clear();
    event.push_str(hook_event_name);

    let process_id = codex_process_id().await?;
    let adapter_version = installed_codex_version().await?;
    let facts = HookRuntimeFacts {
        process_id,
        process_nonce: opaque_digest("process", &process_id.to_string()),
        adapter_version,
    };
    let Some(dispatch) = map_hook_input(&value, &facts)? else {
        return Ok(());
    };
    let registration = serde_json::to_value(dispatch.registration)?;
    let event = serde_json::to_value(dispatch.event)?;
    let turn = dispatch
        .turn
        .map(|turn| {
            serde_json::to_value(CodexHookEventFrame::Turn {
                v: CODEX_HOOK_PROTOCOL_VERSION,
                turn,
            })
        })
        .transpose()?;
    timeout(HOOK_DELIVERY_TIMEOUT, async {
        deliver(paths, CODEX_HOOK_PROTOCOL_VERSION, &registration, &event).await?;
        // Second connection, after the entry: one connection carries one event. The entry goes
        // first so a turn that says "working" is never on screen before the prompt that caused
        // it, and so losing the second delivery costs a turn state rather than a message.
        if let Some(turn) = turn {
            deliver(paths, CODEX_HOOK_PROTOCOL_VERSION, &registration, &turn).await?;
        }
        Ok(())
    })
    .await
    .map_err(|_| anyhow!("Ciao hook delivery timed out"))?
}

/// Walks up from this process until it finds the Codex binary that invoked the hook.
///
/// Codex exports no PID, so this is the only way to name the agent process — and naming it
/// wrongly is not a silent degradation: `agent_bridge` refuses a registration whose claimed
/// process the connection does not descend from, so a wrong answer means no session at all.
async fn codex_process_id() -> Result<u32> {
    let mut pid = std::os::unix::process::parent_id();
    for _ in 0..MAX_CODEX_ANCESTRY {
        if pid == 0 {
            break;
        }
        if process_command(pid)
            .await
            .is_some_and(|command| command_is_codex(&command))
        {
            return Ok(pid);
        }
        let Some(parent) = process_parent(pid).await else {
            break;
        };
        if parent == 0 || parent == pid {
            break;
        }
        pid = parent;
    }
    bail!("the Codex process that invoked this hook could not be identified")
}

/// The first word of the command line is the binary. Matching on its file name keeps a `cwd`,
/// a prompt, or a path that happens to contain "codex" from nominating an unrelated process.
fn command_is_codex(command: &str) -> bool {
    command
        .split_ascii_whitespace()
        .next()
        .and_then(|binary| std::path::Path::new(binary).file_name())
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "codex")
}

async fn installed_codex_version() -> Result<String> {
    let output = timeout(
        HOOK_VERSION_TIMEOUT,
        tokio::process::Command::new("codex")
            .arg("--version")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| anyhow!("Codex version check timed out"))??;
    parse_codex_version_output(&output)
}

/// `codex --version` answers `codex-cli 0.147.0`.
pub(crate) fn parse_codex_version_output(output: &std::process::Output) -> Result<String> {
    if !output.status.success() || output.stdout.is_empty() || output.stdout.len() > 256 {
        bail!("Codex returned an invalid version response");
    }
    let version = std::str::from_utf8(&output.stdout)?
        .trim()
        .strip_prefix("codex-cli ")
        .ok_or_else(|| anyhow!("Codex version response has an unknown format"))?;
    if version.is_empty()
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        bail!("Codex version response is invalid");
    }
    Ok(version.into())
}

/// Maps one hook payload to a registration plus one event, or to nothing at all.
///
/// Returning `None` is not a failure. An observer registration overwrites the session's turn
/// every time it refreshes, so an event that cannot say what the turn is would clobber the one
/// the last event established. Compaction and subagent events are exactly that, and dropping
/// them costs only a heartbeat the prompt/tool/stop events already provide.
fn map_hook_input(value: &Value, facts: &HookRuntimeFacts) -> Result<Option<HookDispatch>> {
    let object = object(value)?;
    let session_id = required_string(object, "session_id")?;
    valid_opaque_id(session_id).map_err(|_| anyhow!("Codex thread ID is invalid"))?;
    let cwd = required_string(object, "cwd")?;
    let event_name = required_string(object, "hook_event_name")?;
    let timestamp = unix_now();
    // The shared classifier (Spec 017 §3), plus the prover: a 0.x minor is a breaking change
    // by convention and stays refused on the version string alone — but a schema-extract
    // verdict this machine already holds is proof, and proof admits (Spec 017 §4.3). Same
    // composed rule as the daemon's registration path.
    let supported = classify_vendor_version(&facts.adapter_version, PINNED_CODEX_VERSION)
        .admitted()
        || crate::codex_carry::is_carried(&facts.adapter_version);

    let (event, turn) = if !supported {
        // An untested build registers so the person can see why nothing is happening, and says
        // nothing else: a payload whose shape has not been re-established is not evidence.
        (
            CodexHookEventFrame::Heartbeat {
                v: CODEX_HOOK_PROTOCOL_VERSION,
            },
            None,
        )
    } else {
        match event_name {
            "SessionStart" => (
                CodexHookEventFrame::Heartbeat {
                    v: CODEX_HOOK_PROTOCOL_VERSION,
                },
                Some(TurnState::Idle),
            ),
            "UserPromptSubmit" => {
                let turn_id = required_string(object, "turn_id")?;
                let (text, truncation) =
                    bounded_text(required_string(object, "prompt")?, MAX_TIMELINE_TEXT_BYTES);
                (
                    CodexHookEventFrame::UpsertEntry {
                        v: CODEX_HOOK_PROTOCOL_VERSION,
                        entry: Box::new(WireTimelineEntry {
                            source_id: opaque_digest("prompt", turn_id),
                            source_revision: 1,
                            timestamp,
                            state: "complete".into(),
                            kind: "user_message".into(),
                            body: TimelineBody::Text { text },
                            truncation,
                        }),
                    },
                    Some(running(turn_id)),
                )
            }
            "PreToolUse" => (
                tool_event(object, timestamp, "streaming", "running", 1)?,
                Some(running(required_string(object, "turn_id")?)),
            ),
            "PostToolUse" => (
                tool_event(object, timestamp, "complete", "completed", 2)?,
                Some(running(required_string(object, "turn_id")?)),
            ),
            // Codex has no streaming display hook, so this is the whole of the assistant's
            // answer and it arrives once, at the end of the turn it closes.
            "Stop" => {
                let turn_id = required_string(object, "turn_id")?;
                let (text, truncation) = bounded_text(
                    required_string(object, "last_assistant_message")?,
                    MAX_TIMELINE_TEXT_BYTES,
                );
                (
                    CodexHookEventFrame::UpsertEntry {
                        v: CODEX_HOOK_PROTOCOL_VERSION,
                        entry: Box::new(WireTimelineEntry {
                            source_id: opaque_digest("message", turn_id),
                            source_revision: 1,
                            timestamp,
                            state: "complete".into(),
                            kind: "assistant_message".into(),
                            body: TimelineBody::Text { text },
                            truncation,
                        }),
                    },
                    Some(TurnState::Completed {
                        run_id: Some(run_id(turn_id)),
                    }),
                )
            }
            // The one hook that says "needs you" (ADR 005). Codex names no reason of its own
            // here, so the categorical kind is the reason: it is a permission gate.
            "PermissionRequest" => (
                CodexHookEventFrame::Notification {
                    v: CODEX_HOOK_PROTOCOL_VERSION,
                    kind: "permission_prompt".into(),
                },
                Some(match object.get("turn_id").and_then(Value::as_str) {
                    Some(turn_id) if valid_opaque_id(&run_id(turn_id)).is_ok() => {
                        TurnState::AwaitingInteraction {
                            run_id: Some(run_id(turn_id)),
                        }
                    }
                    _ => TurnState::AwaitingInteraction { run_id: None },
                }),
            ),
            "SessionEnd" => (
                CodexHookEventFrame::SessionEnd {
                    v: CODEX_HOOK_PROTOCOL_VERSION,
                },
                Some(TurnState::Idle),
            ),
            // GAP(drift): an unknown event name goes untallied here, unlike the Claude hook,
            // because this adapter has nothing safe to ride the name on — any dispatch carries
            // a registration, and an observer registration overwrites the session's turn (the
            // doc comment above). Tallying would mean inventing an event that says nothing
            // about the turn, which is the exact clobber this `None` exists to avoid. Revisit
            // when Spec 017 Phase 2 reworks the gate in this file anyway.
            _ => return Ok(None),
        }
    };

    Ok(Some(HookDispatch {
        registration: AttachedHookRegister {
            v: CODEX_HOOK_PROTOCOL_VERSION,
            message_type: "register".into(),
            adapter: "codex".into(),
            adapter_version: facts.adapter_version.clone(),
            mode: "tui_hook".into(),
            session_id: session_id.into(),
            process_nonce: facts.process_nonce.clone(),
            process_id: facts.process_id,
            workspace_display: workspace_display(cwd),
            // The working directory, and only that. `transcript_path` stays out: it points at
            // the whole conversation on disk and the host reads history through the vendor's
            // own protocol instead.
            workspace_path: cwd.to_owned(),
        },
        event,
        turn,
    }))
}

fn running(turn_id: &str) -> TurnState {
    TurnState::Running {
        run_id: run_id(turn_id),
        activity: "responding".into(),
    }
}

fn tool_event(
    object: &Map<String, Value>,
    timestamp: u64,
    state: &str,
    status: &str,
    source_revision: u64,
) -> Result<CodexHookEventFrame> {
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
    Ok(CodexHookEventFrame::UpsertEntry {
        v: CODEX_HOOK_PROTOCOL_VERSION,
        entry: Box::new(WireTimelineEntry {
            source_id: opaque_digest("tool", tool_use_id),
            source_revision,
            timestamp,
            state: state.into(),
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
        }),
    })
}

fn opaque_digest(namespace: &str, value: &str) -> String {
    format!(
        "codex.{namespace}.{}",
        keyed_digest(CODEX_DIGEST_DOMAIN, namespace, value)
    )
}

fn run_id(turn_id: &str) -> String {
    codex_run_id(turn_id)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn facts() -> HookRuntimeFacts {
        HookRuntimeFacts {
            process_id: 42,
            process_nonce: "0123456789abcdef0123456789abcdef".into(),
            adapter_version: PINNED_CODEX_VERSION.into(),
        }
    }

    /// Field-for-field the payloads Codex 0.146.0 wrote to a hook's stdin on 2026-08-01.
    fn common(event: &str) -> Value {
        json!({
            "session_id": "019fbfaf-d4fc-7452-99b7-53b47c5e7e8f",
            "transcript_path": "/private/synthetic/sessions/2026/08/01/rollout-019fbfaf.jsonl",
            "cwd": "/private/synthetic/Fixture workspace",
            "hook_event_name": event,
            "model": "gpt-5.6-sol",
            "permission_mode": "bypassPermissions"
        })
    }

    fn turn(mut value: Value) -> Value {
        value["turn_id"] = json!("019fbfaf-d510-7a53-8f65-908113821582");
        value
    }

    #[test]
    fn a_prompt_becomes_an_entry_and_opens_a_turn_without_leaking_the_transcript() {
        let mut prompt = turn(common("UserPromptSubmit"));
        prompt["prompt"] = json!("Run the shell command: echo hello. Then reply done.");
        let mapped = map_hook_input(&prompt, &facts()).unwrap().unwrap();

        let registration = serde_json::to_string(&mapped.registration).unwrap();
        assert!(!registration.contains("rollout-019fbfaf"));
        assert_eq!(mapped.registration.workspace_display, "Fixture workspace");
        assert_eq!(
            mapped.registration.workspace_path,
            "/private/synthetic/Fixture workspace"
        );
        // The turn rides on its own frame, never on the registration: a registration that
        // reported `running` was refused by the supervisor, which closed the connection and
        // dropped the prompt entirely while `Stop` still landed.
        assert!(mapped.turn.as_ref().unwrap().is_authoritative_working());

        let CodexHookEventFrame::UpsertEntry { entry, .. } = mapped.event else {
            panic!("expected a user entry");
        };
        assert!(entry.source_id.starts_with("codex.prompt."));
        assert!(!entry.source_id.contains("019fbfaf-d510"));
        assert_eq!(
            entry.body,
            TimelineBody::Text {
                text: "Run the shell command: echo hello. Then reply done.".into()
            }
        );
    }

    #[test]
    fn a_tool_call_is_one_entry_that_completes_in_place() {
        let mut pre = turn(common("PreToolUse"));
        pre["tool_name"] = json!("Bash");
        pre["tool_use_id"] = json!("exec-3b838622-b8b1-40a5-93cd-3d7cfb7d2845");
        pre["tool_input"] = json!({"command": "echo hello"});
        let mut post = pre.clone();
        post["hook_event_name"] = json!("PostToolUse");
        post["tool_response"] = json!("hello\n");

        let first = map_hook_input(&pre, &facts()).unwrap().unwrap().event;
        let second = map_hook_input(&post, &facts()).unwrap().unwrap().event;
        let (
            CodexHookEventFrame::UpsertEntry { entry: first, .. },
            CodexHookEventFrame::UpsertEntry { entry: second, .. },
        ) = (first, second)
        else {
            panic!("expected two tool entries");
        };
        // One card that completes, not two cards. Same source, rising revision.
        assert_eq!(first.source_id, second.source_id);
        assert!(second.source_revision > first.source_revision);
        assert_eq!(first.state, "streaming");
        assert_eq!(second.state, "complete");
        assert_eq!(first.kind, "tool");
        // The vendor's identifier never leaves; the argument that names the step does.
        assert!(!first.source_id.contains("exec-3b838622"));
        let TimelineBody::Tool { tool } = second.body else {
            panic!("expected a tool body");
        };
        assert_eq!(tool.name, "Bash");
        assert_eq!(tool.status, "completed");
        assert!(tool.input_preview.unwrap().contains("echo hello"));
        assert_eq!(tool.result_preview.as_deref(), Some("\"hello\\n\""));
    }

    #[test]
    fn stop_carries_the_whole_answer_and_closes_the_turn() {
        let mut stop = turn(common("Stop"));
        stop["stop_hook_active"] = json!(false);
        stop["last_assistant_message"] = json!("Done.");
        let mapped = map_hook_input(&stop, &facts()).unwrap().unwrap();
        assert!(matches!(
            mapped.turn,
            Some(TurnState::Completed { run_id: Some(_) })
        ));
        let CodexHookEventFrame::UpsertEntry { entry, .. } = mapped.event else {
            panic!("expected an assistant entry");
        };
        assert_eq!(entry.kind, "assistant_message");
        assert_eq!(
            entry.body,
            TimelineBody::Text {
                text: "Done.".into()
            }
        );
    }

    #[test]
    fn an_event_that_cannot_name_the_turn_is_dropped_rather_than_clobbering_it() {
        // A registration overwrites the session's turn, so a compaction event sent as a
        // heartbeat would reset a running turn to whatever this hook happened to guess.
        for event in [
            "PreCompact",
            "PostCompact",
            "SubagentStart",
            "SubagentStop",
            "SomethingCodexAddedLater",
        ] {
            assert!(
                map_hook_input(&common(event), &facts()).unwrap().is_none(),
                "{event} should not be forwarded"
            );
        }
    }

    #[test]
    fn a_permission_request_is_attention_rather_than_timeline_content() {
        let mapped = map_hook_input(&turn(common("PermissionRequest")), &facts())
            .unwrap()
            .unwrap();
        assert_eq!(
            mapped.event,
            CodexHookEventFrame::Notification {
                v: CODEX_HOOK_PROTOCOL_VERSION,
                kind: "permission_prompt".into()
            }
        );
        assert!(matches!(
            mapped.turn,
            Some(TurnState::AwaitingInteraction { .. })
        ));

        // Codex may raise one before a turn exists; the turn is then unnamed, not invented.
        let mapped = map_hook_input(&common("PermissionRequest"), &facts())
            .unwrap()
            .unwrap();
        assert_eq!(
            mapped.turn,
            Some(TurnState::AwaitingInteraction { run_id: None })
        );
    }

    #[test]
    fn an_unsupported_version_reports_only_its_own_unsupportedness() {
        // One minor past the pin. Like its sibling in codex_adapter.rs, this literal has to move
        // with every minor bump or it silently starts asserting the supported path.
        let mut unsupported = facts();
        unsupported.adapter_version = "0.148.0".into();
        let mut prompt = turn(common("UserPromptSubmit"));
        prompt["prompt"] = json!("Synthetic prompt.");
        let mapped = map_hook_input(&prompt, &unsupported).unwrap().unwrap();
        assert_eq!(mapped.registration.adapter_version, "0.148.0");
        assert!(matches!(
            mapped.event,
            CodexHookEventFrame::Heartbeat { .. }
        ));
        assert_eq!(mapped.turn, None);
        // The prompt text is not forwarded by a build whose payload shape is unestablished.
        assert!(
            !serde_json::to_string(&mapped.event)
                .unwrap()
                .contains("Synthetic prompt.")
        );
    }

    #[test]
    fn a_malformed_payload_is_refused_rather_than_guessed() {
        // Every turn-scoped event needs its turn ID; a missing one is not a turn of `None`.
        assert!(map_hook_input(&common("UserPromptSubmit"), &facts()).is_err());
        assert!(map_hook_input(&turn(common("Stop")), &facts()).is_err());
        let mut no_workspace = turn(common("Stop"));
        no_workspace["cwd"] = json!("");
        no_workspace["last_assistant_message"] = json!("Done.");
        assert!(map_hook_input(&no_workspace, &facts()).is_err());
    }

    #[test]
    fn the_version_response_is_parsed_strictly() {
        let output = |stdout: &str| std::process::Output {
            status: std::process::Command::new("true").status().unwrap(),
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        };
        assert_eq!(
            parse_codex_version_output(&output("codex-cli 0.147.0\n")).unwrap(),
            "0.147.0"
        );
        for hostile in ["0.147.0", "codex 0.147.0", "codex-cli beta", ""] {
            assert!(parse_codex_version_output(&output(hostile)).is_err());
        }
    }

    #[test]
    fn only_a_binary_named_codex_can_be_the_agent_process() {
        assert!(command_is_codex(
            "/Users/x/.local/share/mise/installs/node/24.13.0/lib/node_modules/@openai/codex/node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/bin/codex"
        ));
        assert!(command_is_codex("codex resume --last"));
        // A path or prompt that merely contains the word must not nominate a process.
        assert!(!command_is_codex("/bin/sh -c 'cd /src/codex && make'"));
        assert!(!command_is_codex("node /usr/lib/codex/wrapper.js"));
        assert!(!command_is_codex(""));
    }
}
