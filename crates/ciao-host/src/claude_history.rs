//! Claude's own transcript, mapped into the canonical timeline.
//!
//! Hooks report only what happened while Ciao was watching, and deliver it best-effort: a daemon
//! restart, a `claude --resume`, everything said before the plugin loaded, and the fraction of
//! hook deliveries that miss their budget all leave holes that nothing else fills. The transcript
//! is the conversation of record, so this reads it — read-only, in memory, never persisted (ADR
//! 004's metadata-only store is untouched; the phone already receives this content over the
//! encrypted stream, by a different route).
//!
//! The mapping is the managed worker's `canonicalHistory` (worker.mjs), line for line, so one
//! transcript draws one conversation whichever adapter is holding it. The shared fixture
//! `protocol/fixtures/phase5/claude-history-v1.json` is that contract and both implementations
//! are tested against it. What differs is only the reader in front of the mapping: the worker
//! is handed the SDK's chain-selected `SessionMessage[]`, and this reads the file in order with
//! the SDK's own record filter. The two agree for every linear conversation; after a `/rewind`
//! the file still holds the abandoned branch, which this shows and the SDK does not. A
//! compaction summary is skipped here (the vendor flags it `isCompactSummary`), which the SDK's
//! projection cannot see.
//!
//! JSONL entry shapes are the vendor's internal format, release-unstable by its own
//! documentation, so every shape this build does not recognise is tolerated and tallied into
//! the drift ledger by name (Spec 017 §4.2), never guessed at.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    io::{BufRead, BufReader, Read, Seek, SeekFrom},
    path::Path,
    sync::{Mutex, OnceLock},
    time::UNIX_EPOCH,
};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    agent_adapter::WireTimelineEntry,
    agent_protocol::{
        MAX_AGENT_FRAME_BYTES, MAX_TIMELINE_TEXT_BYTES, MAX_TOOL_INPUT_PREVIEW_BYTES,
        MAX_TOOL_RESULT_PREVIEW_BYTES, TimelineBody, ToolTimelineBody, Truncation,
    },
    agent_session::{AgentSessionSupervisor, NormalizedTimelineEntry},
    claude_hook::{is_synthetic_prompt, opaque_digest},
};

/// How much of a transcript a registration backfill reads. Measured: the largest of 120
/// transcripts written on the owner's machine in 30 days was 41.6 MB, so this reads every one of
/// them whole. The read streams line by line; memory is bounded by the canonical output and the
/// longest record, not by this.
pub(crate) const BACKFILL_READ_BYTES: u64 = 64 * 1024 * 1024;
/// How much a turn-end reconcile reads: the newest end, where the turn that just finished is.
pub(crate) const TURN_READ_BYTES: u64 = 8 * 1024 * 1024;
/// One transcript record. The longest measured was 1.4 MB; a longer one is dropped as a hole
/// rather than buffered, and everything before it goes with it so no hidden gap is drawn.
const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
/// The worker's canonical output bounds, which are also the host's per-session timeline bounds.
const MAX_HISTORY_ENTRIES: usize = 4096;
const MAX_HISTORY_BYTES: usize = 4 * 1024 * 1024;
/// The worker's `MAX_TEXT_BYTES`. Named separately so a change to one side of the fixture's
/// contract is a change to a named constant here, not an accident of sharing.
const HISTORY_TEXT_BYTES: usize = MAX_TIMELINE_TEXT_BYTES;
/// `{"v":1,"type":"snapshot_entry","entry":` and the closing brace: the envelope the worker
/// preflights each entry in.
const SNAPSHOT_ENTRY_ENVELOPE_BYTES: usize = 40;

/// Record types this build reads past on purpose: conversation metadata, not conversation.
/// Grounded against Claude Code's own transcripts on the owner's machine; a type outside this
/// list is tallied as drift, so the list is what keeps a vendor rename visible.
const METADATA_RECORD_TYPES: &[&str] = &[
    "agent-name",
    "agent-setting",
    "ai-title",
    "artifact-autoreact-ledger",
    "artifact-comment-monitor",
    "atis-latch",
    "attachment",
    "bridge-session",
    "continued-in",
    "cost-state",
    "custom-title",
    "file-history-delta",
    "file-history-snapshot",
    "frame-link",
    "history-suppression",
    "last-prompt",
    "mode",
    "permission-mode",
    "pr-link",
    "progress",
    "queue-operation",
    "relocated",
    "summary",
    "system",
    "worktree-state",
];

/// Content blocks this build has grounded. `image` is grounded and still drawn as a categorical
/// card — the phone has no renderer for it — which is a decision, not drift.
const GROUNDED_CONTENT_BLOCKS: &[&str] = &[
    "text",
    "thinking",
    "redacted_thinking",
    "tool_use",
    "tool_result",
    "image",
];

/// Which adapter's source IDs a mapping produces. The content is identical; only the identity
/// differs, because each must join the live events of its own adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceScheme {
    /// The attached hooks' digests: a prompt by its `promptId` (what `UserPromptSubmit` carries
    /// as `prompt_id`), a tool by its `tool_use_id`. A reply has no hook-side key to join —
    /// `MessageDisplay` names a random per-display ID — so it gets its own namespace.
    Attached,
    /// The managed worker's literal source IDs, so its live stream lands on the same rows.
    Managed,
}

/// A mapped transcript, newest part within the bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TranscriptHistory {
    pub(crate) entries: Vec<NormalizedTimelineEntry>,
    /// The conversation from its first record: nothing was left unread and nothing was cut to
    /// fit. Anything less advertises a boundary rather than claiming the start.
    pub(crate) complete: bool,
}

/// The attached hook's source namespace for a `MessageDisplay` row (`claude_hook` digests the
/// display's own random ID under `message`). Nothing in the transcript can name one, so these
/// are the live-only rows a turn-end reconcile pairs with the replies the record holds.
pub(crate) const LIVE_DISPLAY_PREFIX: &str = "claude.message.";

/// Sessions already backfilled, so a transcript is read once per process incarnation rather
/// than on every hook event.
///
/// ponytail: one process-wide set cleared wholesale past its ceiling, as `codex_history` does.
/// A rare second read is idempotent — every row it would add is already present.
fn claim(session_id: &str, process_generation: u64) -> bool {
    static CLAIMED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let Ok(mut claimed) = CLAIMED.get_or_init(|| Mutex::new(HashSet::new())).lock() else {
        return false;
    };
    if claimed.len() > 512 {
        claimed.clear();
    }
    claimed.insert(format!("{session_id}:{process_generation}"))
}

/// Fills a newly registered session from Claude's transcript, in the background: a hook
/// holding its connection open has a budget measured against Claude's own hook timeout, and a
/// read of tens of megabytes is nobody's wait. `Attached` pairs with an attached observer,
/// `Managed` with a worker whose own reader refused the transcript.
pub(crate) fn spawn_backfill(
    sessions: AgentSessionSupervisor,
    session_id: String,
    vendor_session_id: String,
    process_generation: u64,
    scheme: SourceScheme,
) {
    if !claim(&session_id, process_generation) {
        return;
    }
    tokio::spawn(async move {
        let read = tokio::task::spawn_blocking(move || {
            read_session_history(&vendor_session_id, scheme, BACKFILL_READ_BYTES)
        })
        .await;
        let Ok(Some(history)) = read else {
            tracing::debug!(session = %session_id, "no Claude transcript to backfill from");
            return;
        };
        let count = history.entries.len();
        let complete = history.complete;
        match sessions.backfill_bridge_history(
            &session_id,
            Some(process_generation),
            history.entries,
            complete,
            live_only_prefix(scheme),
        ) {
            Ok(()) => {
                tracing::info!(session = %session_id, count, complete, "Claude history reconciled")
            }
            Err(error) => tracing::debug!(error = %error, "backfilling Claude history failed"),
        }
    });
}

/// Repairs the turns that just ended from the newest end of the transcript: rows whose hooks
/// never arrived, a tool whose completion was lost, a reply cut by a lost display chunk.
pub(crate) fn spawn_turn_reconcile(
    sessions: AgentSessionSupervisor,
    session_id: String,
    vendor_session_id: String,
    process_generation: u64,
) {
    tokio::spawn(async move {
        let read = tokio::task::spawn_blocking(move || {
            read_session_history(&vendor_session_id, SourceScheme::Attached, TURN_READ_BYTES)
        })
        .await;
        let Ok(Some(history)) = read else {
            return;
        };
        if let Err(error) = sessions.reconcile_bridge_turn(
            &session_id,
            Some(process_generation),
            history.entries,
            Some(LIVE_DISPLAY_PREFIX),
        ) {
            tracing::debug!(error = %error, "reconciling a Claude turn failed");
        }
    });
}

fn live_only_prefix(scheme: SourceScheme) -> Option<&'static str> {
    match scheme {
        SourceScheme::Attached => Some(LIVE_DISPLAY_PREFIX),
        // A managed worker names its live rows exactly as the record does.
        SourceScheme::Managed => None,
    }
}

/// Reads `vendor_session_id`'s transcript, if Claude has one on disk.
pub(crate) fn read_session_history(
    vendor_session_id: &str,
    scheme: SourceScheme,
    read_bytes: u64,
) -> Option<TranscriptHistory> {
    let path = crate::claude_transcript::session_transcript_path(vendor_session_id)?;
    read_history(&path, scheme, read_bytes)
}

/// Streams the newest `read_bytes` of a transcript through the mapping. `None` when the file
/// cannot be read at all, which callers treat as "nothing known", never as "nothing said".
pub(crate) fn read_history(
    path: &Path,
    scheme: SourceScheme,
    read_bytes: u64,
) -> Option<TranscriptHistory> {
    let file = fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }
    // Fixed at open: a live session keeps appending, and chasing a growing file would make the
    // read unbounded. What lands after this length is the live tail's to deliver.
    let length = metadata.len();
    let start = length.saturating_sub(read_bytes);
    let created_at_ms = metadata
        .created()
        .or_else(|_| metadata.modified())
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok());
    let mut reader = BufReader::new(file);
    reader.seek(SeekFrom::Start(start)).ok()?;
    let mut reader = reader.take(length - start);
    let mut mapper = HistoryMapper::new(scheme, created_at_ms);
    let mut line = Vec::new();
    if start > 0 {
        // The read begins mid-conversation, and mid-line: what precedes is unread, not absent.
        mapper.truncated = true;
        read_bounded_line(&mut reader, &mut line, MAX_RECORD_BYTES).ok()?;
    }
    loop {
        match read_bounded_line(&mut reader, &mut line, MAX_RECORD_BYTES).ok()? {
            Line::End => break,
            Line::Oversized => mapper.hole(),
            Line::Record { terminated } => {
                if line.iter().all(u8::is_ascii_whitespace) {
                    continue;
                }
                match serde_json::from_slice::<Value>(&line) {
                    Ok(record) => mapper.push_record(&record),
                    // An unterminated last line is a record still being written.
                    Err(_) if !terminated => {}
                    Err(_) => crate::drift::note("claude", "transcript", "invalid", "record", None),
                }
            }
        }
    }
    Some(mapper.finish())
}

enum Line {
    Record { terminated: bool },
    Oversized,
    End,
}

/// One line, never buffering more than `limit` bytes of it. An over-long line is consumed and
/// reported rather than held.
fn read_bounded_line(
    reader: &mut impl BufRead,
    line: &mut Vec<u8>,
    limit: usize,
) -> std::io::Result<Line> {
    line.clear();
    let mut oversized = false;
    let mut read_any = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(match (read_any, oversized) {
                (false, _) => Line::End,
                (true, true) => Line::Oversized,
                (true, false) => Line::Record { terminated: false },
            });
        }
        read_any = true;
        let newline = available.iter().position(|byte| *byte == b'\n');
        let chunk = newline.unwrap_or(available.len());
        if !oversized {
            if line.len() + chunk > limit {
                oversized = true;
                line.clear();
            } else {
                line.extend_from_slice(&available[..chunk]);
            }
        }
        let consumed = newline.map_or(chunk, |index| index + 1);
        reader.consume(consumed);
        if newline.is_some() {
            return Ok(if oversized {
                Line::Oversized
            } else {
                Line::Record { terminated: true }
            });
        }
    }
}

/// Whether the SDK's reader would hand this record to `canonicalHistory` (and whether the
/// transcript's own flags say it is machinery). Tallies a record type nobody has decided about.
fn conversation_record(record: &Value) -> bool {
    let Some(record_type) = record.get("type").and_then(Value::as_str) else {
        crate::drift::note("claude", "transcript", "invalid", "type", None);
        return false;
    };
    match record_type {
        "user" | "assistant" => {
            record.get("uuid").and_then(Value::as_str).is_some()
                && !truthy(record.get("isMeta"))
                && !truthy(record.get("isSidechain"))
                && !truthy(record.get("teamName"))
                && !truthy(record.get("isCompactSummary"))
        }
        known if METADATA_RECORD_TYPES.contains(&known) => false,
        unknown => {
            crate::drift::note("claude", "transcript", "unknown_record", unknown, None);
            false
        }
    }
}

/// JavaScript truthiness, which is what the SDK's filter applies to these flags.
fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|value| value != 0.0),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(_) | Value::Object(_)) => true,
    }
}

struct Slot {
    entry: NormalizedTimelineEntry,
    bytes: usize,
}

/// `canonicalHistory`, streamed. Entries are kept newest-last within the bounds as they are
/// produced, which gives the same retained suffix as bounding at the end: an entry only ever
/// grows, and a suffix that was over a bound once stays over it.
struct HistoryMapper {
    scheme: SourceScheme,
    created_at_ms: Option<u64>,
    slots: VecDeque<Slot>,
    /// Absolute index of `slots[0]`, so `by_source` stays valid across eviction.
    base: usize,
    by_source: HashMap<String, usize>,
    /// Sources dropped off the old end. A later record that updates one (a result for a call
    /// already evicted) would have updated a row that is gone anyway, so it is ignored rather
    /// than resurrected out of order.
    evicted: HashSet<String>,
    bytes: usize,
    /// Attached prompts already keyed by their `promptId`; a second human record sharing one
    /// is keyed by its own record ID instead of overwriting the first.
    prompts: HashSet<String>,
    messages: usize,
    truncated: bool,
}

impl HistoryMapper {
    fn new(scheme: SourceScheme, created_at_ms: Option<u64>) -> Self {
        Self {
            scheme,
            created_at_ms,
            slots: VecDeque::new(),
            base: 0,
            by_source: HashMap::new(),
            evicted: HashSet::new(),
            bytes: 0,
            prompts: HashSet::new(),
            messages: 0,
            truncated: false,
        }
    }

    fn push_record(&mut self, record: &Value) {
        if !conversation_record(record) {
            return;
        }
        let index = self.messages;
        self.messages += 1;
        let timestamp = self.timestamp(record, index);
        let uuid = record
            .get("uuid")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let message = record.get("message").filter(|message| message.is_object());
        let content = message.and_then(|message| message.get("content"));
        if record.get("type").and_then(Value::as_str) == Some("user") {
            let text = text_from_content(content);
            if !text.is_empty() && !is_synthetic_prompt(&text) {
                let source = self.user_source(record, uuid);
                self.upsert(source, timestamp, "user_message", text_body(&text));
            }
            match content {
                Some(Value::Array(blocks)) => {
                    for (block_index, block) in blocks.iter().enumerate() {
                        let block_type = block.get("type").and_then(Value::as_str);
                        if block_type == Some("text") {
                            continue;
                        }
                        if block_type == Some("tool_result")
                            && let Some(tool_use_id) =
                                block.get("tool_use_id").and_then(Value::as_str)
                        {
                            let status = if block.get("is_error") == Some(&Value::Bool(true)) {
                                "failed"
                            } else {
                                "complete"
                            };
                            let result = text_from_content(block.get("content"));
                            let source = self.source("tool", tool_use_id);
                            self.upsert_tool(source, timestamp, None, status, None, Some(result));
                            continue;
                        }
                        note_content(block_type);
                        let source = self.source("unsupported", &format!("{uuid}-{block_index}"));
                        self.upsert(
                            source,
                            timestamp,
                            "unsupported",
                            unsupported_body("claude_history_content"),
                        );
                    }
                }
                None | Some(Value::String(_)) => {}
                Some(_) => {
                    let source = self.source("unsupported", uuid);
                    self.upsert(
                        source,
                        timestamp,
                        "unsupported",
                        unsupported_body("claude_history_message"),
                    );
                }
            }
            return;
        }

        let text = text_from_content(content);
        if !text.is_empty() {
            let key = message
                .and_then(|message| message.get("id"))
                .and_then(Value::as_str)
                .unwrap_or(uuid);
            let source = self.source("assistant", key);
            self.upsert(source, timestamp, "assistant_message", text_body(&text));
        }
        let blocks = match content {
            Some(Value::Array(blocks)) => blocks,
            None | Some(Value::String(_)) => return,
            Some(_) => {
                let source = self.source("unsupported", uuid);
                self.upsert(
                    source,
                    timestamp,
                    "unsupported",
                    unsupported_body("claude_history_message"),
                );
                return;
            }
        };
        for (block_index, block) in blocks.iter().enumerate() {
            let block_type = block.get("type").and_then(Value::as_str);
            if matches!(block_type, Some("thinking" | "redacted_thinking" | "text")) {
                continue;
            }
            if block_type == Some("tool_use")
                && let Some(id) = block.get("id").and_then(Value::as_str)
            {
                let source = self.source("tool", id);
                let name = safe_tool_name(block.get("name"));
                let input = json_text(block.get("input"));
                self.upsert_tool(source, timestamp, Some(name), "running", Some(input), None);
                continue;
            }
            note_content(block_type);
            let source = self.source("unsupported", &format!("{uuid}-{block_index}"));
            self.upsert(
                source,
                timestamp,
                "unsupported",
                unsupported_body("claude_history_content"),
            );
        }
    }

    /// `messageTimestamp`: the record's own time, else the session start plus its position.
    fn timestamp(&self, record: &Value, index: usize) -> u64 {
        if let Some(seconds) = record
            .get("timestamp")
            .and_then(Value::as_str)
            .and_then(rfc3339_seconds)
        {
            return seconds.max(1);
        }
        let beginning = self
            .created_at_ms
            .map_or_else(crate::hook_common::unix_now, |created| created / 1000)
            .max(1);
        beginning.saturating_add(index as u64)
    }

    fn user_source(&mut self, record: &Value, uuid: &str) -> String {
        if self.scheme == SourceScheme::Attached
            && let Some(prompt_id) = record.get("promptId").and_then(Value::as_str)
            && self.prompts.insert(prompt_id.to_owned())
        {
            return opaque_digest("prompt", prompt_id);
        }
        self.source("user", uuid)
    }

    fn source(&self, prefix: &str, key: &str) -> String {
        match (self.scheme, prefix) {
            (SourceScheme::Managed, _) => managed_source_id(prefix, key),
            (SourceScheme::Attached, "assistant") => opaque_digest("reply", key),
            (SourceScheme::Attached, _) => opaque_digest(prefix, key),
        }
    }

    fn upsert(&mut self, source: String, timestamp: u64, kind: &str, body: MappedBody) {
        if self.evicted.contains(&source) {
            return;
        }
        if let Some(&index) = self.by_source.get(&source) {
            let slot = &mut self.slots[index - self.base];
            slot.entry.source_revision = slot.entry.source_revision.saturating_add(1);
            slot.entry.timestamp = timestamp;
            "complete".clone_into(&mut slot.entry.state);
            kind.clone_into(&mut slot.entry.kind);
            slot.entry.body = body.body;
            slot.entry.truncation = body.truncation;
            let bytes = entry_bytes(&slot.entry);
            self.bytes = self.bytes - slot.bytes + bytes;
            slot.bytes = bytes;
        } else {
            let entry = NormalizedTimelineEntry {
                source_id: source.clone(),
                source_revision: 1,
                timestamp,
                state: "complete".into(),
                kind: kind.into(),
                body: body.body,
                truncation: body.truncation,
            };
            let bytes = entry_bytes(&entry);
            self.bytes += bytes;
            self.by_source.insert(source, self.base + self.slots.len());
            self.slots.push_back(Slot { entry, bytes });
        }
        while self.slots.len() > MAX_HISTORY_ENTRIES || self.bytes > MAX_HISTORY_BYTES {
            self.evict_oldest();
        }
    }

    fn upsert_tool(
        &mut self,
        source: String,
        timestamp: u64,
        name: Option<String>,
        status: &str,
        input: Option<String>,
        result: Option<String>,
    ) {
        if self.evicted.contains(&source) {
            return;
        }
        let existing = self
            .by_source
            .get(&source)
            .map(|index| &self.slots[index - self.base].entry);
        let previous = existing.and_then(|entry| match &entry.body {
            TimelineBody::Tool { tool } => Some(tool.clone()),
            _ => None,
        });
        let effective_status = match &previous {
            Some(previous)
                if status == "running"
                    && matches!(previous.status.as_str(), "complete" | "failed") =>
            {
                previous.status.clone()
            }
            _ => status.to_owned(),
        };
        let mut body = tool_body(
            name.or_else(|| previous.as_ref().map(|tool| tool.name.clone()))
                .unwrap_or_else(|| "tool".into()),
            effective_status,
            input.or_else(|| {
                previous
                    .as_ref()
                    .and_then(|tool| tool.input_preview.clone())
            }),
            result.or_else(|| {
                previous
                    .as_ref()
                    .and_then(|tool| tool.result_preview.clone())
            }),
        );
        if let Some(existing) = existing
            && existing.truncation.truncated
            && !body.truncation.truncated
        {
            body.truncation = existing.truncation.clone();
        }
        self.upsert(source, timestamp, "tool", body);
    }

    fn evict_oldest(&mut self) {
        let Some(slot) = self.slots.pop_front() else {
            return;
        };
        self.base += 1;
        self.bytes -= slot.bytes;
        self.by_source.remove(&slot.entry.source_id);
        self.evicted.insert(slot.entry.source_id);
        self.truncated = true;
    }

    /// A record that could not be read sits somewhere in the middle. Keeping what came before
    /// it would draw a gap nobody can see, so the older part goes and the result says so.
    fn hole(&mut self) {
        while !self.slots.is_empty() {
            self.evict_oldest();
        }
        self.truncated = true;
    }

    fn finish(mut self) -> TranscriptHistory {
        // A call persisted with no result is no longer demonstrably running.
        for slot in &mut self.slots {
            if let TimelineBody::Tool { tool } = &mut slot.entry.body
                && tool.status == "running"
            {
                "unknown".clone_into(&mut tool.status);
            }
        }
        // The worker's frame preflight: an entry whose snapshot frame cannot fit takes the
        // older part with it, so what remains is one contiguous newest tail.
        let unfit = self
            .slots
            .iter()
            .rposition(|slot| slot.bytes + SNAPSHOT_ENTRY_ENVELOPE_BYTES > MAX_AGENT_FRAME_BYTES);
        if let Some(unfit) = unfit {
            self.slots.drain(..=unfit);
            self.truncated = true;
        }
        let mut entries = Vec::with_capacity(self.slots.len());
        for slot in self.slots {
            if slot.entry.validate().is_ok() {
                entries.push(slot.entry);
            } else {
                // Unreachable by construction; if it ever is, the same contiguity rule holds.
                entries.clear();
                self.truncated = true;
            }
        }
        TranscriptHistory {
            entries,
            complete: !self.truncated,
        }
    }
}

fn note_content(block_type: Option<&str>) {
    match block_type {
        Some(grounded) if GROUNDED_CONTENT_BLOCKS.contains(&grounded) => {}
        Some(unknown) => {
            crate::drift::note("claude", "transcript", "unknown_content", unknown, None);
        }
        None => crate::drift::note("claude", "transcript", "invalid", "content_block", None),
    }
}

struct MappedBody {
    body: TimelineBody,
    truncation: Truncation,
}

fn content_bound(truncated: bool) -> Truncation {
    Truncation {
        truncated,
        reason_code: truncated.then(|| "content_bound".to_owned()),
        original_bytes: None,
    }
}

fn text_body(text: &str) -> MappedBody {
    let (text, truncated) = crate::hook_common::truncate_utf8(text, HISTORY_TEXT_BYTES);
    MappedBody {
        body: TimelineBody::Text { text },
        truncation: content_bound(truncated),
    }
}

fn tool_body(
    name: String,
    status: String,
    input: Option<String>,
    result: Option<String>,
) -> MappedBody {
    let input =
        input.map(|input| crate::hook_common::truncate_utf8(&input, MAX_TOOL_INPUT_PREVIEW_BYTES));
    let result = result
        .map(|result| crate::hook_common::truncate_utf8(&result, MAX_TOOL_RESULT_PREVIEW_BYTES));
    let truncated =
        input.as_ref().is_some_and(|(_, cut)| *cut) || result.as_ref().is_some_and(|(_, cut)| *cut);
    MappedBody {
        body: TimelineBody::Tool {
            tool: ToolTimelineBody {
                name,
                status,
                input_preview: input.map(|(text, _)| text),
                result_preview: result.map(|(text, _)| text),
            },
        },
        truncation: content_bound(truncated),
    }
}

fn unsupported_body(reason_code: &str) -> MappedBody {
    MappedBody {
        body: TimelineBody::Unsupported {
            reason_code: reason_code.into(),
        },
        truncation: content_bound(false),
    }
}

/// `textFromContent`: a string, or a content array's text blocks joined with nothing between.
fn text_from_content(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|block| block.get("text").and_then(Value::as_str))
            .collect(),
        _ => String::new(),
    }
}

/// `safeToolName`: vendor tool names become tokens. The worker replaces per UTF-16 code unit,
/// so a character outside the Basic Multilingual Plane becomes two underscores here as well.
fn safe_tool_name(name: Option<&Value>) -> String {
    let raw = match name {
        None | Some(Value::Null) => "tool".to_owned(),
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
    };
    let mut token = String::new();
    for character in raw.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
            token.push(character);
        } else {
            for _ in 0..character.len_utf16() {
                token.push('_');
            }
        }
    }
    token.truncate(64);
    if token.is_empty() {
        "tool".into()
    } else {
        token
    }
}

/// `jsonText`. Object keys come out sorted where the worker keeps insertion order; the two
/// agree whenever the vendor wrote them sorted, which the fixture pins.
fn json_text(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "{}".into(),
        Some(value) => serde_json::to_string(value).unwrap_or_default(),
    }
}

/// `sourceID` in worker.mjs: the readable form when it is a valid source ID, a digest otherwise.
fn managed_source_id(prefix: &str, key: &str) -> String {
    let raw = format!("{prefix}-{key}");
    if raw.len() <= 128
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return raw;
    }
    let digest = Sha256::digest(raw.as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{prefix}-{}", &hex[..32])
}

/// What the worker measures an entry by: its JSON encoding.
fn entry_bytes(entry: &NormalizedTimelineEntry) -> usize {
    serde_json::to_vec(&WireTimelineEntry {
        source_id: entry.source_id.clone(),
        source_revision: entry.source_revision,
        timestamp: entry.timestamp,
        state: entry.state.clone(),
        kind: entry.kind.clone(),
        body: entry.body.clone(),
        truncation: entry.truncation.clone(),
    })
    .map_or(usize::MAX / 2, |bytes| bytes.len())
}

/// Whole seconds of an RFC 3339 instant — `2023-11-14T22:13:20.000Z`, the shape Claude writes —
/// or `None`, in which case the caller falls back exactly as the worker's `Date.parse` miss does.
fn rfc3339_seconds(value: &str) -> Option<u64> {
    let bytes = value.as_bytes();
    let digits = |range: std::ops::Range<usize>| -> Option<i64> {
        let slice = bytes.get(range)?;
        if slice.is_empty() || !slice.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(slice).ok()?.parse().ok()
    };
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let (year, month, day) = (digits(0..4)?, digits(5..7)?, digits(8..10)?);
    let (hour, minute, second) = (digits(11..13)?, digits(14..16)?, digits(17..19)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let mut rest = 19;
    if bytes.get(rest) == Some(&b'.') {
        rest += 1;
        let fraction = bytes[rest..]
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if fraction == 0 {
            return None;
        }
        rest += fraction;
    }
    let offset = match bytes.get(rest..)? {
        [b'Z' | b'z'] => 0,
        [sign @ (b'+' | b'-'), ..] if bytes.len() == rest + 6 && bytes[rest + 3] == b':' => {
            let hours = digits(rest + 1..rest + 3)?;
            let minutes = digits(rest + 4..rest + 6)?;
            let magnitude = hours * 3600 + minutes * 60;
            if *sign == b'+' { magnitude } else { -magnitude }
        }
        _ => return None,
    };
    // Days from the civil calendar (Howard Hinnant's algorithm).
    let shifted = if month <= 2 { year - 1 } else { year };
    let era = shifted.div_euclid(400);
    let year_of_era = shifted - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second - offset;
    u64::try_from(seconds).ok()
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn fixture() -> Value {
        serde_json::from_str(include_str!(
            "../../../protocol/fixtures/phase5/claude-history-v1.json"
        ))
        .expect("the shared fixture parses")
    }

    fn map_records(
        records: &[Value],
        scheme: SourceScheme,
        created_at_ms: u64,
    ) -> TranscriptHistory {
        let mut mapper = HistoryMapper::new(scheme, Some(created_at_ms));
        for record in records {
            mapper.push_record(record);
        }
        mapper.finish()
    }

    fn expected_source(expected: &Value, scheme: SourceScheme) -> String {
        match scheme {
            SourceScheme::Managed => expected["managed_source"].as_str().unwrap().to_owned(),
            SourceScheme::Attached => opaque_digest(
                expected["attached_source"][0].as_str().unwrap(),
                expected["attached_source"][1].as_str().unwrap(),
            ),
        }
    }

    /// The contract with the managed worker: one transcript, one conversation, under either
    /// adapter's identities. worker.test.ts asserts the same file against canonicalHistory.
    #[test]
    fn both_schemes_draw_the_shared_fixture_exactly_as_the_worker_does() {
        let fixture = fixture();
        let records = fixture["records"].as_array().unwrap();
        let created_at_ms = fixture["created_at_ms"].as_u64().unwrap();
        for scheme in [SourceScheme::Managed, SourceScheme::Attached] {
            let mapped = map_records(records, scheme, created_at_ms);
            assert!(mapped.complete, "{scheme:?}: nothing was cut");
            let expected: Vec<NormalizedTimelineEntry> = fixture["expected"]
                .as_array()
                .unwrap()
                .iter()
                .map(|expected| NormalizedTimelineEntry {
                    source_id: expected_source(expected, scheme),
                    source_revision: expected["source_revision"].as_u64().unwrap(),
                    timestamp: expected["timestamp"].as_u64().unwrap(),
                    state: expected["state"].as_str().unwrap().into(),
                    kind: expected["kind"].as_str().unwrap().into(),
                    body: serde_json::from_value(expected["body"].clone()).unwrap(),
                    truncation: serde_json::from_value(expected["truncation"].clone()).unwrap(),
                })
                .collect();
            assert_eq!(mapped.entries, expected, "{scheme:?}");
        }
    }

    /// The live hooks key a prompt by `prompt_id` and a tool by `tool_use_id` under this same
    /// digest domain; a history row that did not land on the same key would be drawn twice.
    #[test]
    fn attached_history_keys_prompts_and_tools_the_way_the_hooks_do() {
        let fixture = fixture();
        let mapped = map_records(
            fixture["records"].as_array().unwrap(),
            SourceScheme::Attached,
            1,
        );
        let sources: HashSet<_> = mapped
            .entries
            .iter()
            .map(|entry| entry.source_id.as_str())
            .collect();
        for (namespace, key) in [
            ("prompt", "p-01"),
            ("tool", "toolu-01"),
            ("tool", "toolu-02"),
        ] {
            assert!(
                sources.contains(opaque_digest(namespace, key).as_str()),
                "{namespace}:{key}"
            );
        }
        // Vendor identifiers stay behind the digest.
        assert!(!format!("{:?}", mapped.entries).contains("toolu-01"));
    }

    fn write_transcript(lines: &[String]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        for line in lines {
            writeln!(file, "{line}").unwrap();
        }
        file
    }

    fn user_line(uuid: &str, text: &str) -> String {
        serde_json::json!({
            "type": "user", "uuid": uuid, "promptId": uuid, "promptSource": "typed",
            "timestamp": "2023-11-14T22:13:20.000Z",
            "message": {"role": "user", "content": text}
        })
        .to_string()
    }

    #[test]
    fn a_whole_transcript_is_complete_and_a_tail_read_says_it_is_not() {
        let lines: Vec<_> = (0..40)
            .map(|index| user_line(&format!("u-{index:02}"), &format!("prompt {index}")))
            .collect();
        let file = write_transcript(&lines);
        let whole = read_history(file.path(), SourceScheme::Managed, BACKFILL_READ_BYTES).unwrap();
        assert!(whole.complete);
        assert_eq!(whole.entries.len(), 40);

        // Only the newest end: the first partial line is skipped, not misread, and the result
        // does not claim the conversation's start.
        let tail = read_history(file.path(), SourceScheme::Managed, 1024).unwrap();
        assert!(!tail.complete);
        assert!(!tail.entries.is_empty() && tail.entries.len() < 40);
        assert_eq!(
            tail.entries.last().unwrap().body,
            TimelineBody::Text {
                text: "prompt 39".into()
            }
        );
    }

    #[test]
    fn the_newest_entries_are_kept_within_the_count_and_byte_bounds() {
        let lines: Vec<_> = (0..MAX_HISTORY_ENTRIES + 10)
            .map(|index| user_line(&format!("u-{index}"), &format!("prompt {index}")))
            .collect();
        let file = write_transcript(&lines);
        let read = read_history(file.path(), SourceScheme::Managed, BACKFILL_READ_BYTES).unwrap();
        assert!(!read.complete);
        assert_eq!(read.entries.len(), MAX_HISTORY_ENTRIES);
        assert_eq!(read.entries[0].source_id, "user-u-10");

        let large = "x".repeat(40 * 1024);
        let lines: Vec<_> = (0..200)
            .map(|index| user_line(&format!("b-{index}"), &format!("{index}:{large}")))
            .collect();
        let file = write_transcript(&lines);
        let read = read_history(file.path(), SourceScheme::Managed, BACKFILL_READ_BYTES).unwrap();
        assert!(!read.complete);
        let bytes: usize = read.entries.iter().map(entry_bytes).sum();
        assert!(bytes <= MAX_HISTORY_BYTES);
        assert_eq!(read.entries.last().unwrap().source_id, "user-b-199");
    }

    /// A record too long to buffer is a hole in the middle; the older part is dropped with it
    /// rather than drawn as though it joined what follows.
    #[test]
    fn an_unreadable_record_drops_everything_before_it() {
        let oversized = user_line("u-big", &"y".repeat(MAX_RECORD_BYTES + 1));
        let lines = vec![
            user_line("u-before", "before"),
            oversized,
            user_line("u-after", "after"),
        ];
        let file = write_transcript(&lines);
        let read = read_history(file.path(), SourceScheme::Managed, BACKFILL_READ_BYTES).unwrap();
        assert!(!read.complete);
        assert_eq!(
            read.entries
                .iter()
                .map(|entry| entry.source_id.as_str())
                .collect::<Vec<_>>(),
            vec!["user-u-after"]
        );
    }

    /// A line still being written when the read reached it is not drift and not an error.
    #[test]
    fn an_unterminated_last_line_is_tolerated_silently() {
        let mut file = write_transcript(&[user_line("u-1", "done")]);
        write!(file, "{{\"type\":\"user\",\"uuid\":\"u-2\",\"mess").unwrap();
        let read = read_history(file.path(), SourceScheme::Managed, BACKFILL_READ_BYTES).unwrap();
        assert!(read.complete);
        assert_eq!(read.entries.len(), 1);
    }

    #[test]
    fn a_missing_transcript_is_unknown_rather_than_empty() {
        assert!(
            read_history(
                Path::new("/nonexistent/ciao-claude-history.jsonl"),
                SourceScheme::Attached,
                BACKFILL_READ_BYTES
            )
            .is_none()
        );
    }

    /// Spec 017 §4.2: shapes this build does not know are tallied by name and tolerated — a
    /// record type is skipped, a content block becomes the categorical card — and grounded
    /// metadata the reader skips on purpose is never tallied.
    #[test]
    fn future_shaped_transcript_input_is_tallied_by_name_and_tolerated() {
        let records = [
            serde_json::json!({"type": "ScopeFutureRecord", "uuid": "f-1", "payload": "CANARY"}),
            serde_json::json!({"type": "ai-title", "aiTitle": "CANARY"}),
            serde_json::json!({"type": "assistant", "uuid": "f-2", "timestamp": "2023-11-14T22:13:20Z",
                "message": {"id": "m", "content": [{"type": "ScopeFutureBlock", "text": "CANARY"}]}}),
        ];
        let mapped = map_records(&records, SourceScheme::Attached, 1);
        assert_eq!(
            mapped
                .entries
                .iter()
                .map(|entry| entry.kind.as_str())
                .collect::<Vec<_>>(),
            vec!["unsupported"]
        );
        let ledger = crate::drift::snapshot();
        let claude = &ledger.vendors["claude"];
        for (kind, name) in [
            ("unknown_record", "ScopeFutureRecord"),
            ("unknown_content", "ScopeFutureBlock"),
        ] {
            assert!(
                claude
                    .signatures
                    .iter()
                    .any(|note| note.surface == "transcript"
                        && note.kind == kind
                        && note.name == name),
                "{kind} {name}"
            );
        }
        assert!(
            !claude
                .signatures
                .iter()
                .any(|note| note.surface == "transcript" && note.name == "ai-title")
        );
        assert!(!serde_json::to_string(&ledger).unwrap().contains("CANARY"));
        assert!(!format!("{:?}", mapped.entries).contains("CANARY"));
    }

    /// The prefix names exactly the rows the attached hook creates from `MessageDisplay`, and
    /// nothing the transcript mapping produces.
    #[test]
    fn the_live_display_prefix_is_the_hooks_and_never_the_records() {
        assert!(opaque_digest("message", "display-id").starts_with(LIVE_DISPLAY_PREFIX));
        let fixture = fixture();
        let mapped = map_records(
            fixture["records"].as_array().unwrap(),
            SourceScheme::Attached,
            1,
        );
        assert!(
            mapped
                .entries
                .iter()
                .all(|entry| !entry.source_id.starts_with(LIVE_DISPLAY_PREFIX))
        );
    }

    /// An attached observer registration as the Claude hook produces one.
    fn grounded_registration(index: usize) -> crate::agent_session::NormalizedRegistration {
        use crate::agent_protocol::{
            AgentCapabilities, CommandCapabilities, InteractionCapabilities, Observation, TurnState,
        };
        crate::agent_session::NormalizedRegistration {
            history_boundary: None,
            upstream_identity: format!("grounded-session-{index}"),
            process_nonce: format!("grounded-nonce-{index:04}"),
            process_id: std::process::id(),
            adapter_family: "Claude".into(),
            adapter_version: crate::claude_adapter::PINNED_CLAUDE_VERSION.into(),
            topology: "attached".into(),
            compatible: true,
            version_state: "grounded".into(),
            tested_version: crate::claude_adapter::PINNED_CLAUDE_VERSION.into(),
            workspace_display: "Grounded".into(),
            workspace_path: None,
            observation: Observation {
                coverage: "partial".into(),
                reason_code: "claude_hooks_partial".into(),
                last_authoritative_at: None,
            },
            turn: TurnState::Unknown {
                reason_code: "partial_observation".into(),
            },
            capabilities: AgentCapabilities {
                history: "live_tail".into(),
                commands: CommandCapabilities::none(),
                interactions: InteractionCapabilities::none(),
                pending_rehydration: "none".into(),
                terminal_continuity: "unavailable".into(),
            },
            control_owner: "terminal".into(),
        }
    }

    /// Zero model turns, read-only: `CIAO_TEST_CLAUDE_TRANSCRIPTS=1` maps the newest transcripts
    /// in this machine's own Claude store through the attached backfill and a turn-end
    /// reconcile, exactly as the daemon would, and prints sizes, counts and timings only —
    /// never content or identifiers. `CIAO_TEST_CLAUDE_TRANSCRIPTS_DUMP=<file>` additionally
    /// writes each small transcript's managed-scheme source IDs there for an SDK comparison.
    #[tokio::test]
    async fn grounded_real_transcripts_backfill_and_reconcile_when_explicitly_enabled() {
        if std::env::var_os("CIAO_TEST_CLAUDE_TRANSCRIPTS").is_none() {
            return;
        }
        let projects = crate::claude_transcript::claude_projects_dir().expect("a Claude store");
        let now = std::time::SystemTime::now();
        let mut transcripts: Vec<(std::time::SystemTime, std::path::PathBuf)> =
            fs::read_dir(&projects)
                .unwrap()
                .filter_map(Result::ok)
                .filter_map(|project| fs::read_dir(project.path()).ok())
                .flatten()
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| {
                    path.extension()
                        .is_some_and(|extension| extension == "jsonl")
                })
                .filter_map(|path| Some((fs::metadata(&path).ok()?.modified().ok()?, path)))
                // Settled files only: a live session appending between the two reads would make the
                // idempotence check below measure the session, not the reconcile.
                .filter(|(modified, _)| {
                    now.duration_since(*modified)
                        .is_ok_and(|age| age.as_secs() > 120)
                })
                .collect();
        transcripts.sort_by_key(|entry| std::cmp::Reverse(entry.0));
        transcripts.truncate(40);
        let mut dump = std::env::var_os("CIAO_TEST_CLAUDE_TRANSCRIPTS_DUMP")
            .map(|path| fs::File::create(path).unwrap());
        let temp = tempfile::tempdir().unwrap();
        let sessions = AgentSessionSupervisor::load(
            &temp.path().join("agent-metadata.json"),
            crate::workspace::WorkspaceConfig::with_binary_dirs(Vec::new()),
        )
        .unwrap();
        let (mut complete, mut partial, mut entries_total) = (0, 0, 0);
        for (index, (_, path)) in transcripts.iter().enumerate() {
            let size = fs::metadata(path).unwrap().len();
            let began = std::time::Instant::now();
            let read = read_history(path, SourceScheme::Attached, BACKFILL_READ_BYTES)
                .expect("a settled transcript reads");
            let elapsed = began.elapsed().as_millis();
            let mut kinds = std::collections::BTreeMap::new();
            for entry in &read.entries {
                *kinds.entry(entry.kind.as_str()).or_insert(0usize) += 1;
            }
            println!(
                "transcript={index} bytes={size} entries={} complete={} read_ms={elapsed} kinds={kinds:?}",
                read.entries.len(),
                read.complete
            );
            if read.complete {
                complete += 1;
            } else {
                partial += 1;
            }
            entries_total += read.entries.len();

            let registered = sessions
                .register_observer(grounded_registration(index))
                .await
                .unwrap();
            sessions
                .backfill_bridge_history(
                    &registered.session_id,
                    Some(registered.process_generation),
                    read.entries.clone(),
                    read.complete,
                    Some(LIVE_DISPLAY_PREFIX),
                )
                .unwrap();
            let backfilled = sessions.snapshot(&registered.session_id).unwrap();
            backfilled.validate().unwrap();
            assert_eq!(
                backfilled.capabilities.history,
                if read.complete { "full" } else { "live_tail" }
            );
            let tail = read_history(path, SourceScheme::Attached, TURN_READ_BYTES).unwrap();
            sessions
                .reconcile_bridge_turn(
                    &registered.session_id,
                    Some(registered.process_generation),
                    tail.entries,
                    Some(LIVE_DISPLAY_PREFIX),
                )
                .unwrap();
            let reconciled = sessions.snapshot(&registered.session_id).unwrap();
            assert_eq!(
                (reconciled.revision, reconciled.snapshot_epoch),
                (backfilled.revision, backfilled.snapshot_epoch),
                "transcript {index}: a turn reconcile over what the backfill already laid is a no-op"
            );

            if let Some(dump) = dump.as_mut()
                && size <= 4 * 1024 * 1024
                && let Some(stem) = path.file_stem().and_then(|stem| stem.to_str())
            {
                let managed =
                    read_history(path, SourceScheme::Managed, BACKFILL_READ_BYTES).unwrap();
                let sources: Vec<_> = managed
                    .entries
                    .iter()
                    .map(|entry| entry.source_id.as_str())
                    .collect();
                writeln!(
                    dump,
                    "{}",
                    serde_json::json!({"session": stem, "sources": sources})
                )
                .unwrap();
            }
        }
        println!(
            "grounded transcripts={} complete={complete} partial={partial} entries={entries_total}",
            transcripts.len()
        );
    }

    #[test]
    fn timestamps_parse_the_way_date_parse_reads_them() {
        assert_eq!(
            rfc3339_seconds("2023-11-14T22:13:20.000Z"),
            Some(1_700_000_000)
        );
        assert_eq!(rfc3339_seconds("2023-11-14T22:13:20Z"), Some(1_700_000_000));
        assert_eq!(
            rfc3339_seconds("2023-11-14T22:13:20.999Z"),
            Some(1_700_000_000)
        );
        assert_eq!(
            rfc3339_seconds("2023-11-14T23:13:20+01:00"),
            Some(1_700_000_000)
        );
        assert_eq!(rfc3339_seconds("2024-02-29T00:00:00Z"), Some(1_709_164_800));
        for malformed in [
            "",
            "2023-11-14",
            "2023-13-14T22:13:20Z",
            "yesterday",
            "2023-11-14T22:13:20",
        ] {
            assert_eq!(rfc3339_seconds(malformed), None, "{malformed}");
        }
    }

    #[test]
    fn managed_source_ids_digest_exactly_when_the_worker_does() {
        assert_eq!(managed_source_id("tool", "toolu_01"), "tool-toolu_01");
        let long = "k".repeat(200);
        let digested = managed_source_id("user", &long);
        assert!(digested.starts_with("user-") && digested.len() == 5 + 32);
        assert_ne!(managed_source_id("user", "with space"), "user-with space");
    }

    #[test]
    fn tool_names_become_tokens_per_utf16_unit() {
        assert_eq!(safe_tool_name(Some(&Value::from("Bash"))), "Bash");
        assert_eq!(safe_tool_name(Some(&Value::from("a b/c"))), "a_b_c");
        assert_eq!(safe_tool_name(Some(&Value::from("x😀"))), "x__");
        assert_eq!(safe_tool_name(None), "tool");
        assert_eq!(safe_tool_name(Some(&Value::from(""))), "tool");
        assert_eq!(safe_tool_name(Some(&Value::from("z".repeat(80)))).len(), 64);
    }
}
