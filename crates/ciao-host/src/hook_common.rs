//! Vendor-neutral pieces of a Ciao-owned command hook.
//!
//! Extracted from the Claude hook when the Codex hook arrived (Spec 012). These are the bounds,
//! the digests, and the delivery handshake — the parts where a second copy would drift, and
//! where drift means a privacy bound that holds for one vendor and not the other. Vendor payload
//! mapping deliberately stays in each adapter's own hook module.
//!
//! Every function here is silent and fail-open by contract: a hook that cannot reach Ciao must
//! leave the user's terminal session exactly as it was.

use std::{
    fs,
    io::{Read, Write},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use tokio::{net::UnixStream, time::timeout};

use crate::{
    agent_protocol::{Truncation, decode_agent_body, read_agent_frame, write_agent_frame},
    storage::CiaoPaths,
};

/// Budget for the whole five-step delivery. Sized against a vendor's own hook timeout with room
/// for process start, not against how long delivery normally takes: at 750ms a busy daemon —
/// several agent sessions, a phone attached, a directory sweep in flight — dropped about one hook
/// invocation in six, and a dropped prompt event is unrecoverable.
pub(crate) const HOOK_DELIVERY_TIMEOUT: Duration = Duration::from_millis(1500);
/// Per-step bound, kept below the delivery budget so a single wedged step cannot consume it all.
pub(crate) const HOOK_IPC_STEP_TIMEOUT: Duration = Duration::from_millis(600);

/// Longest string guaranteed to be kept inside a serialized tool argument. Generous enough for
/// a command line or a path, small enough that a document holding dozens of strings still fits
/// its envelope — this is the fallback cap `bounded_preview` can always retreat to.
pub(crate) const MAX_PREVIEW_STRING_BYTES: usize = 512;
/// The per-string cap `bounded_preview` tries first. At 512 bytes a Write's content or a
/// command's output was cut to a stub mid-sentence; four times that keeps a readable hunk of
/// it whenever the document as a whole fits its envelope, which is the common case — a tool
/// call holds a handful of strings, not thousands.
pub(crate) const GENEROUS_PREVIEW_STRING_BYTES: usize = 2048;

pub(crate) fn read_bounded_stdin(maximum_bytes: usize) -> Result<Vec<u8>> {
    let mut input = std::io::stdin().lock();
    let mut body = Vec::new();
    let mut scratch = [0_u8; 8192];
    let mut oversized = false;
    loop {
        let read = input.read(&mut scratch)?;
        if read == 0 {
            break;
        }
        if !oversized && body.len().saturating_add(read) <= maximum_bytes {
            body.extend_from_slice(&scratch[..read]);
        } else {
            oversized = true;
        }
    }
    if oversized {
        bail!("hook input exceeded its byte bound");
    }
    Ok(body)
}

pub(crate) fn object(value: &Value) -> Result<&Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| anyhow!("hook input is not an object"))
}

pub(crate) fn required_string<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("hook string field is missing"))
}

pub(crate) fn required_u64(object: &Map<String, Value>, key: &str) -> Result<u64> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("hook integer field is missing"))
}

pub(crate) fn required_bool(object: &Map<String, Value>, key: &str) -> Result<bool> {
    object
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("hook boolean field is missing"))
}

/// The last path component, control characters removed, bounded — the name a person recognizes
/// without the directory tree it sits in.
pub(crate) fn workspace_display(cwd: &str) -> String {
    let display = std::path::Path::new(cwd)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("Workspace");
    let sanitized: String = display
        .chars()
        .filter(|character| !character.is_control())
        .collect();
    let sanitized = sanitized.trim();
    truncate_utf8(
        if sanitized.is_empty() {
            "Workspace"
        } else {
            sanitized
        },
        256,
    )
    .0
}

/// A stable, namespaced digest of a vendor identifier. `domain` separates one vendor's hook
/// protocol from another's, so the same upstream ID under two adapters never collides — and so
/// changing one vendor's domain can never renumber another's live entries.
pub(crate) fn keyed_digest(domain: &[u8], namespace: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(namespace.as_bytes());
    hasher.update(b"\0");
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
    hasher.finalize()[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn bounded_text(value: &str, maximum_bytes: usize) -> (String, Truncation) {
    let original_bytes = value.len();
    let (text, truncated) = truncate_utf8(value, maximum_bytes);
    (
        text,
        if truncated {
            Truncation {
                truncated: true,
                reason_code: Some("adapter_bound".into()),
                original_bytes: Some(original_bytes as u64),
            }
        } else {
            no_truncation()
        },
    )
}

pub(crate) fn truncate_utf8(value: &str, maximum_bytes: usize) -> (String, bool) {
    if value.len() <= maximum_bytes {
        return (value.into(), false);
    }
    let mut boundary = maximum_bytes;
    while !value.is_char_boundary(boundary) {
        boundary = boundary.saturating_sub(1);
    }
    (value[..boundary].into(), true)
}

pub(crate) fn no_truncation() -> Truncation {
    Truncation {
        truncated: false,
        reason_code: None,
        original_bytes: None,
    }
}

/// Serializes a hook's tool arguments or result into the bounded preview iOS parses as JSON to
/// name a step — `file_path` for an edit, `command` for a shell call.
///
/// Long string values are capped in place rather than truncating the serialized text, because
/// a cut JSON document does not parse and the reader falls back to the bare tool name, which
/// is the "Bash / Edit / Bash" wall this exists to remove. Returns whether anything was cut so
/// the entry can say so.
///
/// Two passes, generous first: the tight pass only exists for documents so string-dense that
/// the generous one overflows the envelope, and because it is exactly the old single pass, no
/// input that used to yield a preview can lose one to the generosity.
pub(crate) fn bounded_preview(value: Option<&Value>, limit: usize) -> (Option<String>, bool) {
    let Some(value) = value else {
        return (None, false);
    };
    for cap in [GENEROUS_PREVIEW_STRING_BYTES, MAX_PREVIEW_STRING_BYTES] {
        let mut clipped = false;
        let capped = cap_strings(value, cap, &mut clipped);
        let Ok(text) = serde_json::to_string(&capped) else {
            return (None, false);
        };
        if text.len() <= limit {
            return (Some(text), clipped);
        }
    }
    // Capping every string can still leave a document over the bound if it holds thousands of
    // them. Omitting beats sending something the reader cannot parse.
    (None, true)
}

fn cap_strings(value: &Value, cap: usize, clipped: &mut bool) -> Value {
    match value {
        Value::String(text) if text.len() > cap => {
            *clipped = true;
            let mut end = cap;
            while end > 0 && !text.is_char_boundary(end) {
                end -= 1;
            }
            Value::String(text[..end].to_string())
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| cap_strings(item, cap, clipped))
                .collect(),
        ),
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, field)| (key.clone(), cap_strings(field, cap, clipped)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// The register/registered/event/applied handshake on the local agent socket. One connection
/// carries exactly one event, which is what makes a hook process disposable.
pub(crate) async fn deliver(
    paths: &CiaoPaths,
    protocol_version: u8,
    registration: &Value,
    event: &Value,
) -> Result<()> {
    // Every step is named and timed, and a failure carries the times of the steps that already
    // succeeded. `deadline has elapsed` said only that *a* step went over, which is not enough to
    // act on: a slow `connect` means the daemon is not accepting, while a slow `read` means it
    // accepted and then did not answer, and those have nothing to do with each other. Roughly 3%
    // of hook deliveries fail this way, and three separate attempts to explain it from profiles
    // and correlations were wrong, so the next attempt reads the answer off the failure itself.
    let mut trail = String::new();
    macro_rules! step {
        ($name:literal, $future:expr) => {{
            let began = std::time::Instant::now();
            let outcome = timeout(HOOK_IPC_STEP_TIMEOUT, $future).await;
            let elapsed = began.elapsed().as_millis();
            match outcome {
                Ok(Ok(value)) => {
                    use std::fmt::Write as _;
                    let _ = write!(trail, " {}={}ms", $name, elapsed);
                    value
                }
                Ok(Err(error)) => {
                    return Err(anyhow::Error::from(error)).with_context(|| {
                        format!("{} failed after {}ms;{}", $name, elapsed, trail)
                    });
                }
                Err(_) => {
                    return Err(anyhow!("{} exceeded {}ms;{}", $name, elapsed, trail));
                }
            }
        }};
    }

    let mut stream = step!("connect", UnixStream::connect(&paths.agent_socket_file));
    step!(
        "write-registration",
        write_agent_frame(&mut stream, registration)
    );
    let registered = step!("read-registered", read_agent_frame(&mut stream));
    validate_response(&registered, protocol_version, "registered")?;

    step!("write-event", write_agent_frame(&mut stream, event));
    let applied = step!("read-applied", read_agent_frame(&mut stream));
    validate_response(&applied, protocol_version, "event_applied")
}

fn validate_response(body: &[u8], protocol_version: u8, expected_type: &str) -> Result<()> {
    let value: Value = decode_agent_body(body).map_err(|_| anyhow!("invalid hook response"))?;
    let object = object(&value)?;
    if object.get("v").and_then(Value::as_u64) != Some(u64::from(protocol_version))
        || object.get("type").and_then(Value::as_str) != Some(expected_type)
    {
        bail!("unexpected hook response");
    }
    Ok(())
}

/// Opt-in by existence: nothing is written unless the trace file is already there, so the
/// default remains silent and turning it off is `rm`. Best-effort throughout — tracing a hook
/// must never be able to fail one.
///
/// Every hook failure is swallowed by its caller so a local Ciao outage cannot add noise to the
/// attached terminal, which also means a hook that stops observing is invisible: a prompt event
/// that never lands leaves the conversation unnamed, with nothing anywhere saying why. This
/// records the categorical outcome when — and only when — the owner has asked for it.
pub(crate) fn trace_outcome(paths: &CiaoPaths, file_name: &str, event: &str, result: &Result<()>) {
    let path = paths.logs_dir.join(file_name);
    if !path.exists() {
        return;
    }
    let event = if event.is_empty() { "?" } else { event };
    // The full chain, not just the outermost layer: this file exists only because the owner
    // asked a question that the categorical answer did not settle. No prompt or message text
    // reaches an error here — bodies are only read on the success path.
    let outcome = match result {
        Ok(()) => "ok".to_owned(),
        Err(error) => format!("error: {error:#}"),
    };
    let line = format!("{} {event} {outcome}\n", unix_now());
    let _ = fs::OpenOptions::new()
        .create(false)
        .append(true)
        .open(&path)
        .and_then(|mut file| file.write_all(line.as_bytes()));
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| duration.as_secs().max(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_protocol::MAX_LIVE_TEXT_DELTA_BYTES;
    use serde_json::json;

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
    fn a_digest_is_stable_and_separated_by_domain_and_namespace() {
        let claude = keyed_digest(b"ciao-claude-hook-v1\0", "prompt", "abc");
        assert_eq!(
            claude,
            keyed_digest(b"ciao-claude-hook-v1\0", "prompt", "abc")
        );
        // Two vendors observing the same upstream identifier must not collide, and renaming
        // one domain must never renumber the other's live entries.
        assert_ne!(
            claude,
            keyed_digest(b"ciao-codex-hook-v1\0", "prompt", "abc")
        );
        assert_ne!(
            claude,
            keyed_digest(b"ciao-claude-hook-v1\0", "tool", "abc")
        );
        assert_ne!(
            claude,
            keyed_digest(b"ciao-claude-hook-v1\0", "prompt", "abd")
        );
    }

    #[test]
    fn an_oversized_argument_is_capped_but_still_parses_as_json() {
        let (preview, clipped) = bounded_preview(
            Some(&json!({
                "file_path": "/tmp/generated.swift",
                "content": "x".repeat(GENEROUS_PREVIEW_STRING_BYTES * 4),
            })),
            16 * 1024,
        );
        let preview = preview.expect("a capped argument is still sent");
        let parsed: Value = serde_json::from_str(&preview).expect("the preview parses");
        assert_eq!(parsed["file_path"], json!("/tmp/generated.swift"));
        assert!(parsed["content"].as_str().unwrap().len() <= GENEROUS_PREVIEW_STRING_BYTES);
        assert!(clipped);
    }

    #[test]
    fn a_mid_size_argument_survives_whole_when_the_document_fits() {
        // Between the tight cap and the generous one: the size the old single pass cut to a
        // stub even though the whole document fit its envelope with room to spare.
        let content = "y".repeat(MAX_PREVIEW_STRING_BYTES * 3);
        let (preview, clipped) = bounded_preview(
            Some(&json!({ "file_path": "/tmp/generated.swift", "content": content })),
            16 * 1024,
        );
        let parsed: Value =
            serde_json::from_str(&preview.expect("the document fits")).expect("parses");
        assert_eq!(parsed["content"].as_str().unwrap(), content);
        assert!(!clipped);
    }

    #[test]
    fn a_string_dense_document_falls_back_to_the_tight_cap() {
        // Twelve near-generous strings overflow a 16 KiB envelope at the generous cap. The
        // fallback is exactly the old pass, so a document that yielded a preview before the
        // generous pass existed must still yield one — omission here would be a regression.
        let value = json!(vec!["z".repeat(2000); 12]);
        let (preview, clipped) = bounded_preview(Some(&value), 16 * 1024);
        let parsed: Value =
            serde_json::from_str(&preview.expect("the tight pass still fits")).expect("parses");
        for item in parsed.as_array().unwrap() {
            assert!(item.as_str().unwrap().len() <= MAX_PREVIEW_STRING_BYTES);
        }
        assert!(clipped);
    }

    #[test]
    fn a_document_over_bound_at_both_caps_is_omitted_not_cut() {
        // Thousands of short strings: no single value is capped by either pass, the document
        // is over bound anyway, and a serialized cut would not parse — so it is omitted and
        // said to be.
        let value = json!(
            (0..3000)
                .map(|n| format!("entry-{n:04}"))
                .collect::<Vec<_>>()
        );
        let (preview, clipped) = bounded_preview(Some(&value), 16 * 1024);
        assert_eq!(preview, None);
        assert!(clipped);
    }

    #[test]
    fn a_workspace_name_is_the_basename_without_control_characters() {
        assert_eq!(workspace_display("/private/synthetic/Fixture"), "Fixture");
        assert_eq!(workspace_display("/"), "Workspace");
        assert_eq!(workspace_display("/a/we\u{7}ird"), "weird");
    }
}
