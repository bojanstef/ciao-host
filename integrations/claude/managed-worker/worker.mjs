// Ciao-owned managed Claude worker (Spec 006 §9).
//
// One side speaks the pinned Agent SDK; the other speaks Ciao's bounded
// managed-worker bridge wire over a same-user Unix socket. SDK message types,
// vendor session structures, transcript paths, and credentials never cross to
// the daemon: everything is mapped to canonical entries, receipts, and
// interactions here. Nothing is written to stdout/stderr but categorical lines.
import crypto from "node:crypto";
import net from "node:net";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

const PROTOCOL_VERSION = 1;
const MAX_FRAME_BYTES = 64 * 1024;
const MAX_TEXT_DELTA_BYTES = 16 * 1024;
// A finished message body, mirroring the host's MAX_TIMELINE_TEXT_BYTES — the ceiling the
// timeline actually renders, and what the attached adapter already keeps of a long reply.
// Only streaming deltas stay on MAX_TEXT_DELTA_BYTES, which is a wire-frame bound
// (MAX_LIVE_TEXT_DELTA_BYTES host-side), not a display budget.
const MAX_TEXT_BYTES = 48 * 1024;
const MAX_TOOL_INPUT_PREVIEW_BYTES = 16 * 1024;
const MAX_TOOL_RESULT_PREVIEW_BYTES = 32 * 1024;
// The SDK applies `limit` only after reading the whole transcript. Check the local file size
// first, or a long conversation would turn a nominally bounded history request into an
// unbounded worker allocation. Canonical output is independently held to the host/iOS bound.
const MAX_HISTORY_TRANSCRIPT_BYTES = 4 * 1024 * 1024;
const MAX_HISTORY_CANONICAL_BYTES = 4 * 1024 * 1024;
const MAX_HISTORY_ENTRIES = 4_096;
const HEARTBEAT_MS = 15_000;

const config = {
	socketPath: process.env.CIAO_MANAGED_SOCKET,
	sdkPrefix: process.env.CIAO_MANAGED_SDK_PREFIX,
	sessionID: process.env.CIAO_MANAGED_SESSION_ID,
	spawnToken: process.env.CIAO_MANAGED_SPAWN_TOKEN,
	workspaceLabel: process.env.CIAO_MANAGED_WORKSPACE_LABEL,
	resumeSessionID: process.env.CIAO_MANAGED_RESUME_SESSION_ID || undefined,
	cliVersion: process.env.CIAO_MANAGED_CLI_VERSION,
	sdkVersion: process.env.CIAO_MANAGED_SDK_VERSION,
	cliPath: process.env.CIAO_MANAGED_CLI_PATH || undefined,
	permissionMode: process.env.CIAO_MANAGED_PERMISSION_MODE || undefined,
	// Deliberately not in the required-key guard below: a fresh session has no model to inherit
	// and must start on the vendor's own default rather than one invented here.
	model: process.env.CIAO_MANAGED_MODEL || undefined,
};

// The pinned SDK's own PermissionMode union.
const PERMISSION_MODES = new Set(["default", "acceptEdits", "bypassPermissions", "plan", "dontAsk", "auto"]);
// The pinned SDK's own EffortLevel union. `max` is here because it is reachable for the session
// through applyFlagSettings, even though the persistable settings union leaves it out.
const EFFORT_LEVELS = new Set(["low", "medium", "high", "xhigh", "max"]);
// Ciao's bounds on a published catalogue, mirroring the host's. Enforced here as well as there
// so an over-long vendor list is trimmed at the boundary that can still see what it is trimming,
// rather than failing a frame the host can only reject whole.
const MAX_CATALOGUE_ENTRIES = 16;
const MAX_MODEL_ID_BYTES = 64;
const MAX_MODEL_DISPLAY_NAME_BYTES = 48;
const MAX_EFFORT_LEVELS_PER_MODEL = 8;
// The daemon's `valid_model_id` grammar, mirrored, because one refused frame ends the whole
// bridge. The CLI answers slash commands and notices with synthetic assistant messages whose
// model is "<synthetic>" — an artifact, not a model, and never reportable.
const MODEL_ID_GRAMMAR = /^[A-Za-z0-9._\[\]-]+$/;
// What this session is running under now. Starts at what the host passed and moves only when
// the SDK has accepted a change.
let permissionMode = PERMISSION_MODES.has(config.permissionMode) ? config.permissionMode : "default";
// What is answering now, and how hard it is thinking. Both start unknown on purpose: the SDK is
// lazy and names no model until a turn produces one, so anything reported before that would be
// this worker guessing. The host renders unknown as the vendor's default and never as a model.
let activeModel = null;
let activeEffort = null;
// The catalogue as published, so a command can be checked against what this account can really
// run rather than against a list compiled into Ciao.
let catalogue = [];
// Catalogue id -> the wire id it stands for, for the rows the vendor says resolve. This stays
// worker-side rather than going on the wire: the phone picks from `catalogue` and never needs to
// know that `sonnet` and `claude-sonnet-5` are the same thing. Knowing it is this worker's job,
// because the vendor reports a model in one form and keys the catalogue in the other — see
// `canonicalModel`.
const modelResolutions = new Map();
for (const key of [
	"socketPath",
	"sdkPrefix",
	"sessionID",
	"spawnToken",
	"workspaceLabel",
	"cliVersion",
	"sdkVersion",
]) {
	if (!config[key]) {
		process.stderr.write(`ciao-managed-worker: missing ${key}\n`);
		process.exit(2);
	}
}
// The token is consumed once at registration; drop every Ciao variable so the
// SDK subprocess never inherits worker plumbing.
const childEnv = { ...process.env };
for (const key of Object.keys(childEnv)) {
	if (key.startsWith("CIAO_MANAGED_")) delete childEnv[key];
}

const sdk = await import(
	pathToFileURL(
		path.join(config.sdkPrefix, "node_modules", "@anthropic-ai/claude-agent-sdk", "sdk.mjs"),
	).href
);

// ---------------------------------------------------------------- framing

const socket = net.connect(config.socketPath);
// EOF already means no more daemon commands. Waiting for `close` can strand the worker behind
// queued snapshot writes when the peer stops reading (reproduced on Bun 1.2.23). Registration
// tokens are one-time: exit nonzero so the reaper can store a resumable worker_crash, rather
// than leaving an invisible live worker. Explicit `shutdown` still exits 0 synchronously,
// before any resulting socket event can be delivered.
for (const event of ["error", "end", "close"]) socket.on(event, () => process.exit(1));
await new Promise((resolve, reject) => {
	socket.once("connect", resolve);
	socket.once("error", reject);
});

function writeFrame(value) {
	const body = Buffer.from(JSON.stringify({ v: PROTOCOL_VERSION, ...value }), "utf8");
	if (body.length > MAX_FRAME_BYTES) return false;
	const header = Buffer.alloc(4);
	header.writeUInt32BE(body.length);
	return socket.write(Buffer.concat([header, body]));
}

const inboundHandlers = [];
{
	let buffered = Buffer.alloc(0);
	socket.on("data", (chunk) => {
		buffered = Buffer.concat([buffered, chunk]);
		while (buffered.length >= 4) {
			const length = buffered.readUInt32BE(0);
			if (length === 0 || length > MAX_FRAME_BYTES) {
				socket.destroy();
				return;
			}
			if (buffered.length < 4 + length) return;
			const body = buffered.subarray(4, 4 + length);
			buffered = buffered.subarray(4 + length);
			let frame;
			try {
				frame = JSON.parse(body.toString("utf8"));
			} catch {
				continue;
			}
			for (const handler of inboundHandlers) handler(frame);
		}
	});
}

// ---------------------------------------------------------------- mapping

function boundedText(text, limit) {
	const buffer = Buffer.from(String(text ?? ""), "utf8");
	if (buffer.length <= limit) return { text: buffer.toString("utf8"), truncated: false };
	// Slice on a character boundary so the daemon always receives valid UTF-8.
	return {
		text: buffer.subarray(0, limit).toString("utf8").replace(/�$/, ""),
		truncated: true,
	};
}

function truncation(truncated, reason) {
	return truncated ? { truncated: true, reason_code: reason } : { truncated: false };
}

function nowSeconds() {
	return Math.max(1, Math.floor(Date.now() / 1000));
}

const revisions = new Map();
function nextRevision(sourceID) {
	const revision = (revisions.get(sourceID) ?? 0) + 1;
	revisions.set(sourceID, revision);
	return revision;
}

function sendEntry(type, sourceID, kind, body, state = "complete") {
	writeFrame({
		type,
		entry: {
			source_id: sourceID,
			source_revision: nextRevision(sourceID),
			timestamp: nowSeconds(),
			state,
			kind,
			body: body.body,
			truncation: body.truncation,
		},
	});
}

function textBody(text, limit = MAX_TEXT_BYTES) {
	const bounded = boundedText(text, limit);
	return {
		body: { type: "text", text: bounded.text },
		truncation: truncation(bounded.truncated, "content_bound"),
	};
}

/// One chunk of an entry that is still being written. The host appends it to whatever the
/// source ID already holds and derives `streaming` from `final_chunk`, so the phone draws the
/// caret without the worker ever saying so.
function appendText(sourceID, kind, delta) {
	const bounded = boundedText(delta, MAX_TEXT_DELTA_BYTES);
	writeFrame({
		type: "append_text",
		delta: {
			source_id: sourceID,
			source_revision: nextRevision(sourceID),
			timestamp: nowSeconds(),
			kind,
			delta: bounded.text,
			final_chunk: false,
			truncation: truncation(bounded.truncated, "content_bound"),
		},
	});
}

/// Envelopes Claude wraps around text it delivers through the prompt path itself: background-task
/// wake-ups, sub-agent completions, monitor events, slash-command expansions, injected reminders
/// and `!` bash echoes. A replay carrying one is machinery rather than something a person typed.
///
/// `--replay-user-messages` replays *every* user message, and the worker trusted all of them, so
/// raw `<task-notification>` XML was drawn in the conversation as if the reader had sent it.
///
/// Mirrors `SYNTHETIC_PROMPT_ENVELOPES` in `crates/ciao-host/src/claude_hook.rs`, which the
/// attached adapter has applied since it shipped. Two sites, one rule — change both.
///
/// ponytail: prefix match, same as the Rust side. Someone who pastes one of these verbatim loses
/// one timeline row and nothing else; the prompt still reaches Claude untouched.
const SYNTHETIC_PROMPT_ENVELOPES = [
	"<task-notification>",
	"<system-reminder>",
	"<local-command-caveat>",
	"<local-command-stdout>",
	"<command-name>",
	"<command-message>",
	"<bash-input>",
	"<bash-stdout>",
];

function isSyntheticPrompt(text) {
	const trimmed = (text ?? "").trimStart();
	return SYNTHETIC_PROMPT_ENVELOPES.some((envelope) => trimmed.startsWith(envelope));
}

function toolBody(name, status, input, result) {
	const boundedInput = input === undefined ? undefined : boundedText(input, MAX_TOOL_INPUT_PREVIEW_BYTES);
	const boundedResult =
		result === undefined ? undefined : boundedText(result, MAX_TOOL_RESULT_PREVIEW_BYTES);
	return {
		body: {
			type: "tool",
			tool: {
				name,
				status,
				...(boundedInput ? { input_preview: boundedInput.text } : {}),
				...(boundedResult ? { result_preview: boundedResult.text } : {}),
			},
		},
		truncation: truncation(
			Boolean(boundedInput?.truncated || boundedResult?.truncated),
			"content_bound",
		),
	};
}

/// Tool names are vendor tokens; keep them categorical for the canonical wire.
function safeToolName(name) {
	const token = String(name ?? "tool").replace(/[^A-Za-z0-9._-]/g, "_");
	return token.slice(0, 64) || "tool";
}

function textFromContent(content) {
	if (typeof content === "string") return content;
	if (!Array.isArray(content)) return "";
	return content
		.filter((block) => block?.type === "text" && typeof block.text === "string")
		.map((block) => block.text)
		.join("");
}

/// The same upstream object gets the same source ID in history and in the live stream. That is
/// the reconciliation seam: if the transcript already contains a just-starting turn, the host
/// updates one row rather than drawing a historical copy beside the streamed copy.
function sourceID(prefix, upstreamID) {
	const raw = `${prefix}-${String(upstreamID ?? "")}`;
	if (raw.length <= 128 && /^[A-Za-z0-9._:-]+$/.test(raw)) return raw;
	return `${prefix}-${crypto.createHash("sha256").update(raw).digest("hex").slice(0, 32)}`;
}

function messageTimestamp(message, index, createdAt) {
	const parsed = typeof message?.timestamp === "string" ? Date.parse(message.timestamp) : Number.NaN;
	const parsedSeconds = Math.floor(parsed / 1_000);
	if (Number.isSafeInteger(parsedSeconds)) return Math.max(1, parsedSeconds);
	const createdSeconds = Math.floor(createdAt / 1_000);
	const beginning = Number.isSafeInteger(createdSeconds) ? Math.max(1, createdSeconds) : nowSeconds();
	const fallback = beginning + index;
	return Number.isSafeInteger(fallback) ? fallback : nowSeconds();
}

function jsonText(value) {
	try {
		return JSON.stringify(value ?? {});
	} catch {
		return "";
	}
}

function unsupportedBody(reasonCode) {
	return {
		body: { type: "unsupported", reason_code: reasonCode },
		truncation: truncation(false),
	};
}

/// Maps the documented `SessionMessage[]` reader result into the same canonical vocabulary as
/// live SDK events. The reader has already selected the active parentUuid chain and excluded
/// metadata/sidechains; this layer only decides what the phone may render.
function canonicalHistory(messages, createdAt) {
	const entries = [];
	const bySource = new Map();
	let truncated = false;

	const upsert = (source, timestamp, kind, body, state = "complete") => {
		const existing = bySource.get(source);
		if (existing) {
			existing.source_revision += 1;
			existing.timestamp = timestamp;
			existing.state = state;
			existing.kind = kind;
			existing.body = body.body;
			existing.truncation = body.truncation;
			return existing;
		}
		const entry = {
			source_id: source,
			source_revision: 1,
			timestamp,
			state,
			kind,
			body: body.body,
			truncation: body.truncation,
		};
		bySource.set(source, entry);
		entries.push(entry);
		return entry;
	};

	const upsertTool = (source, timestamp, name, status, input, result) => {
		const existing = bySource.get(source);
		const previous = existing?.body?.type === "tool" ? existing.body.tool : undefined;
		const effectiveStatus =
			status === "running" && ["complete", "failed"].includes(previous?.status)
				? previous.status
				: status;
		const body = toolBody(
			name || previous?.name || "tool",
			effectiveStatus,
			input === undefined ? previous?.input_preview : input,
			result === undefined ? previous?.result_preview : result,
		);
		if (existing?.truncation?.truncated && !body.truncation.truncated) {
			body.truncation = existing.truncation;
		}
		upsert(source, timestamp, "tool", body);
	};

	for (const [messageIndex, historical] of messages.entries()) {
		const timestamp = messageTimestamp(historical, messageIndex, createdAt);
		const message = historical?.message;
		const content = message && typeof message === "object" ? message.content : undefined;
		if (historical?.type === "user") {
			const text = textFromContent(content);
			if (text && !isSyntheticPrompt(text)) {
				upsert(sourceID("user", historical.uuid), timestamp, "user_message", textBody(text));
			}
			if (Array.isArray(content)) {
				for (const [blockIndex, block] of content.entries()) {
					if (block?.type === "text") continue;
					if (block?.type === "tool_result" && typeof block.tool_use_id === "string") {
						const result = textFromContent(block.content);
						upsertTool(
							sourceID("tool", block.tool_use_id),
							timestamp,
							undefined,
							block.is_error === true ? "failed" : "complete",
							undefined,
							result,
						);
						continue;
					}
					upsert(
						sourceID("unsupported", `${historical.uuid}-${blockIndex}`),
						timestamp,
						"unsupported",
						unsupportedBody("claude_history_content"),
					);
				}
			} else if (content !== undefined && typeof content !== "string") {
				upsert(
					sourceID("unsupported", historical.uuid),
					timestamp,
					"unsupported",
					unsupportedBody("claude_history_message"),
				);
			}
			continue;
		}
		if (historical?.type !== "assistant") {
			upsert(
				sourceID("unsupported", historical?.uuid ?? messageIndex),
				timestamp,
				"unsupported",
				unsupportedBody("claude_history_message"),
			);
			continue;
		}

		const text = textFromContent(content);
		if (text) {
			upsert(
				sourceID("assistant", message?.id ?? historical.uuid),
				timestamp,
				"assistant_message",
				textBody(text),
			);
		}
		if (!Array.isArray(content)) {
			if (content !== undefined && typeof content !== "string") {
				upsert(
					sourceID("unsupported", historical.uuid),
					timestamp,
					"unsupported",
					unsupportedBody("claude_history_message"),
				);
			}
			continue;
		}
		for (const [blockIndex, block] of content.entries()) {
			if (["thinking", "redacted_thinking", "text"].includes(block?.type)) continue;
			if (block?.type === "tool_use" && typeof block.id === "string") {
				upsertTool(
					sourceID("tool", block.id),
					timestamp,
					safeToolName(block.name),
					"running",
					jsonText(block.input),
					undefined,
				);
				continue;
			}
			upsert(
				sourceID("unsupported", `${historical.uuid}-${blockIndex}`),
				timestamp,
				"unsupported",
				unsupportedBody("claude_history_content"),
			);
		}
	}

	// A persisted call with no result is no longer demonstrably running. Keep it visible but do
	// not make historical content claim current activity.
	for (const entry of entries) {
		if (entry.body?.type === "tool" && entry.body.tool.status === "running") {
			entry.body.tool.status = "unknown";
		}
	}

	// Raw-text bounds are not frame bounds: JSON escaping can expand one control character sixfold.
	// Preflight the exact envelope writeFrame will encode, or a single hostile entry would be
	// silently skipped while registration still claimed the history was complete.
	let firstFrameSafe = 0;
	for (const [index, entry] of entries.entries()) {
		const bytes = Buffer.byteLength(
			JSON.stringify({ v: PROTOCOL_VERSION, type: "snapshot_entry", entry }),
		);
		if (bytes <= MAX_FRAME_BYTES) continue;
		// Keep one contiguous newest tail. Dropping only this row would hide a hole in the middle
		// while the boundary marker incorrectly claimed that everything missing was earlier.
		firstFrameSafe = index + 1;
		truncated = true;
	}
	const frameEntries = firstFrameSafe === 0 ? entries : entries.slice(firstFrameSafe);
	const entryBytes = frameEntries.map((entry) => Buffer.byteLength(JSON.stringify(entry)));
	let bytes = entryBytes.reduce((total, size) => total + size, 0);
	let firstRetained = 0;
	while (
		frameEntries.length - firstRetained > MAX_HISTORY_ENTRIES ||
		bytes > MAX_HISTORY_CANONICAL_BYTES
	) {
		bytes -= entryBytes[firstRetained] ?? 0;
		firstRetained += 1;
		truncated = true;
	}
	return {
		entries: firstRetained === 0 ? frameEntries : frameEntries.slice(firstRetained),
		truncated,
	};
}

async function loadResumedHistory() {
	if (!config.resumeSessionID) return { entries: [], complete: true };
	try {
		// Search by the explicit session ID. Restricting the reader to the launch cwd loses a
		// conversation after a worktree move even though the resume itself still finds it.
		const info = await sdk.getSessionInfo(config.resumeSessionID);
		if (
			!info ||
			!Number.isSafeInteger(info.fileSize) ||
			info.fileSize < 0 ||
			info.fileSize > MAX_HISTORY_TRANSCRIPT_BYTES
		) {
			return { entries: [], complete: false };
		}
		const messages = await sdk.getSessionMessages(config.resumeSessionID);
		if (!Array.isArray(messages)) return { entries: [], complete: false };
		const mapped = canonicalHistory(messages, info.createdAt);
		for (const entry of mapped.entries) {
			revisions.set(entry.source_id, entry.source_revision);
		}
		return { entries: mapped.entries, complete: !mapped.truncated };
	} catch {
		return { entries: [], complete: false };
	}
}

// Read before the query can receive a prompt. Snapshot bytes therefore precede every live event,
// and the two channels cannot race a duplicate or reorder a turn around its own history.
const resumedHistory = await loadResumedHistory();

// ---------------------------------------------------------------- session

const input = (() => {
	const queue = [];
	const waiters = [];
	let closed = false;
	return {
		push(value) {
			const waiter = waiters.shift();
			if (waiter) waiter({ value, done: false });
			else queue.push(value);
		},
		close() {
			closed = true;
			for (const waiter of waiters.splice(0)) waiter({ value: undefined, done: true });
		},
		async *stream() {
			while (true) {
				if (queue.length > 0) {
					yield queue.shift();
					continue;
				}
				if (closed) return;
				const item = await new Promise((resolve) => waiters.push(resolve));
				if (item.done) return;
				yield item.value;
			}
		},
	};
})();

// command_id -> the uuid streamed for it, so the SDK's replay echo is the
// delivery acknowledgement (grounded: requires --replay-user-messages).
const promptsAwaitingReplay = new Map();
// interaction_id -> { settle, decide } for a pending permission callback.
const pendingInteractions = new Map();

// ------------------------------------------------------- AskUserQuestion

// Claude's own multi-question tool, intercepted rather than approved. `canUseTool` returns
// allow or deny and cannot supply a tool result, and neither can the PreToolUse hook, so the
// phone's answers are held here and swapped into the tool's output by a PostToolUse hook —
// the one documented seam that replaces output for every tool rather than MCP ones alone.
// Without it the tool runs headlessly, finds no interface to ask through, and reports back
// "The user did not answer the questions."
const ASK_USER_QUESTION = "AskUserQuestion";
// The pinned SDK's own `AskUserQuestionInput` bounds, which are also what the host advertises.
const MAX_ASK_QUESTIONS = 4;
const MAX_ASK_OPTIONS = 4;
const MAX_ASK_TEXT_BYTES = 4096;
// tool_use_id -> the AskUserQuestionOutput to substitute once the tool has run.
const answeredQuestions = new Map();

/// The tool's questions as Ciao's canonical schema, or null if the input is not the shape this
/// pin documents — in which case it stays an ordinary permission card rather than becoming a
/// question the phone cannot answer truthfully.
function canonicalQuestions(toolInput) {
	const questions = Array.isArray(toolInput?.questions) ? toolInput.questions : [];
	if (questions.length === 0 || questions.length > MAX_ASK_QUESTIONS) return null;
	const canonical = [];
	for (const [index, question] of questions.entries()) {
		const options = Array.isArray(question?.options) ? question.options : [];
		if (
			typeof question?.question !== "string" ||
			question.question.length === 0 ||
			options.length === 0 ||
			options.length > MAX_ASK_OPTIONS
		) {
			return null;
		}
		const header = typeof question.header === "string" ? question.header : "";
		canonical.push({
			question_id: `q${index}`,
			prompt: boundedText(question.question, MAX_TOOL_INPUT_PREVIEW_BYTES).text,
			response_kind: question.multiSelect === true ? "multi_choice" : "single_choice",
			required: true,
			...(header ? { header: boundedText(header, 64).text } : {}),
			options: options.map((option, position) => {
				const description = typeof option?.description === "string" ? option.description : "";
				return {
					choice_id: `q${index}-o${position}`,
					label: boundedText(String(option?.label ?? ""), 1024).text || `Option ${position + 1}`,
					...(description ? { description: boundedText(description, 1024).text } : {}),
				};
			}),
			// The tool description says an "Other" free-text option is supplied automatically, so
			// a phone without one would be answering a narrower question than the model asked.
			max_text_bytes: MAX_ASK_TEXT_BYTES,
		});
	}
	return canonical;
}

/// The pinned SDK's `AskUserQuestionOutput`: the questions echoed back, plus question text to
/// answer string with multi-select answers comma-separated. Labels are resolved here rather
/// than carried down to the phone and back, so nothing the agent wrote makes a round trip.
function askUserQuestionOutput(toolInput, answers) {
	const byQuestion = new Map((answers ?? []).map((answer) => [answer?.question_id, answer]));
	const spoken = {};
	const echoed = [];
	for (const [index, question] of toolInput.questions.entries()) {
		const answer = byQuestion.get(`q${index}`);
		const chosen = [];
		question.options.forEach((option, position) => {
			if (answer?.choice_ids?.includes(`q${index}-o${position}`)) {
				chosen.push(String(option?.label ?? ""));
			}
		});
		// Free text is the "Other" escape, and it stands alongside any chosen options rather
		// than replacing them: the phone is allowed to send both.
		if (typeof answer?.text === "string" && answer.text.length > 0) chosen.push(answer.text);
		spoken[question.question] = chosen.join(", ");
		echoed.push({ ...question, multiSelect: question.multiSelect === true });
	}
	return { questions: echoed, answers: spoken };
}

function receipt(commandID, state, evidence, reasonCode) {
	writeFrame({
		type: "command_receipt",
		command_id: commandID,
		state,
		...(evidence ? { evidence } : {}),
		...(reasonCode ? { reason_code: reasonCode } : {}),
	});
}

async function canUseTool(toolName, toolInput, options) {
	const interactionID = crypto.randomBytes(16).toString("hex");
	const name = safeToolName(toolName);
	const questions = name === ASK_USER_QUESTION ? canonicalQuestions(toolInput) : null;
	const bounded = boundedText(
		typeof toolInput?.command === "string" ? toolInput.command : JSON.stringify(toolInput ?? {}),
		1024,
	);
	// Grounded at this pin: `title` is absent, so the card is built from the
	// tool name plus a bounded input preview rather than vendor prose. A question carries its
	// own prose in the schema, so its body stays empty rather than repeating it as JSON.
	writeFrame({
		type: "upsert_interaction",
		interaction: {
			interaction_id: interactionID,
			interaction_revision: 1,
			kind: questions ? "question" : "permission",
			created_at: nowSeconds(),
			title: questions
				? questions.length === 1
					? "Claude has a question"
					: `Claude has ${questions.length} questions`
				: `Run ${name}`,
			body: questions ? "" : bounded.text,
			response_schema: questions
				? { type: "questions", questions }
				: {
						type: "choices",
						minimum: 1,
						maximum: 1,
						choices: [
							{ choice_id: "allow-once", label: "Allow once", scope: "once" },
							{ choice_id: "deny", label: "Deny", scope: "request" },
						],
					},
		},
	});
	// The card blocks the turn; the notification is what reaches a pocket. Sent after the
	// interaction frame so the row already shows the card when the phone opens from the push.
	// The only two integrations that could raise a blocking card were the two that could not
	// push about it — this closes the managed half.
	writeFrame({
		type: "notification",
		kind: questions ? "question_prompt" : "permission_prompt",
	});

	// What an inbound response means, decided by the request that raised it. Returns null when
	// the frame cannot answer this request at all, which is refused rather than guessed at.
	const decide = questions
		? (frame) => {
				if (!Array.isArray(frame.answers) || frame.answers.length === 0) return null;
				// Answered, so the tool is allowed to run — and its "did not answer" output is
				// replaced by the PostToolUse hook keyed on this same tool call.
				answeredQuestions.set(options.toolUseID, askUserQuestionOutput(toolInput, frame.answers));
				return { result: { behavior: "allow" }, evidence: "questions_answered" };
			}
		: (frame) => {
				// A frame carrying no choice at all cannot answer this: an unrecognised choice
				// still denies, which is the fail-closed rule, but a *missing* one would make a
				// denial out of a malformed frame rather than out of a decision.
				if (typeof frame.choice_id !== "string") return null;
				return {
					result:
						frame.choice_id === "allow-once"
							? { behavior: "allow" }
							: { behavior: "deny", message: "Denied from Ciao." },
					evidence: "permission_resolved",
				};
			};

	return await new Promise((resolve) => {
		let settled = false;
		const settle = (result, resolution) => {
			if (settled) return;
			settled = true;
			pendingInteractions.delete(interactionID);
			writeFrame({ type: "resolve_interaction", interaction_id: interactionID, resolution });
			resolve(result);
		};
		pendingInteractions.set(interactionID, { settle, decide });
		// An interrupt aborts the request; it is never recorded as a user denial.
		options.signal.addEventListener("abort", () => {
			settle({ behavior: "deny", message: "Interrupted before a decision." }, "expired");
		});
	});
}

const query = sdk.query({
	prompt: input.stream(),
	options: {
		cwd: process.cwd(),
		env: childEnv,
		// Documented SDK isolation: machine-local settings never change managed
		// behavior. The replay flag is what makes delivery acknowledgeable.
		settingSources: [],
		extraArgs: { "replay-user-messages": null },
		includePartialMessages: true,
		// A worker resuming a conversation continues it in the mode that conversation was
		// already in; the host reads that from Claude's own transcript and passes it, and
		// validates it against the SDK's union before it gets here. Unset means a fresh
		// session with nothing to inherit, which starts where a new terminal would.
		permissionMode,
		// Same inheritance rule as the mode: a resumed conversation continues on the model it
		// was already being answered by, which the host read from Claude's own transcript.
		// Unset means a fresh session, which starts wherever the vendor's default is — never
		// on a model chosen here.
		...(config.model ? { model: config.model } : {}),
		canUseTool,
		// Registered here rather than on disk because managed sessions run `settingSources: []`
		// and read no filesystem settings at all. No matcher: this runs for every tool and the
		// map lookup selects, so there is one place for the substitution to stop happening
		// rather than two.
		hooks: {
			PostToolUse: [
				{
					hooks: [
						async (hookInput) => {
							// The effort the turn actually ran at, after any silent downgrade for
							// the chosen model. Absent on models without effort support, which is
							// why effort stays unreported rather than defaulting to a level.
							observeEffort(hookInput?.effort?.level);
							const answered = answeredQuestions.get(hookInput?.tool_use_id);
							if (!answered) return {};
							answeredQuestions.delete(hookInput.tool_use_id);
							return {
								hookSpecificOutput: {
									hookEventName: "PostToolUse",
									updatedToolOutput: answered,
								},
							};
						},
					],
				},
			],
		},
		...(config.resumeSessionID ? { resume: config.resumeSessionID } : {}),
		...(config.cliPath ? { pathToClaudeCodeExecutable: config.cliPath } : {}),
	},
});

// ---------------------------------------------------------------- register

writeFrame({
	type: "register",
	adapter: "claude-managed",
	adapter_version: config.cliVersion,
	sdk_version: config.sdkVersion,
	spawn_token: config.spawnToken,
	session_id: config.sessionID,
	process_nonce: crypto.randomBytes(16).toString("hex"),
	process_id: process.pid,
	workspace_display: config.workspaceLabel,
	resumed: Boolean(config.resumeSessionID),
	history_complete: resumedHistory.complete,
});

inboundHandlers.push((frame) => {
	switch (frame?.type) {
		case "registered":
			writeFrame({ type: "snapshot_start" });
			for (const entry of resumedHistory.entries) {
				writeFrame({ type: "snapshot_entry", entry });
			}
			writeFrame({ type: "snapshot_end" });
			// The mode this worker actually started in, so the phone shows the session's own
			// state rather than whatever it last asked for.
			writeFrame({ type: "permission_mode", mode: permissionMode });
			// A resumed session was launched onto a model the host named, and this worker put that
			// name in `Options.model` itself — so it is a fact about the session rather than a
			// guess at the vendor's default, and the bar can be right from the first paint instead
			// of empty until something answers. A fresh session passes no model and stays silent.
			// Said before the catalogue resolves; `publishCatalogue` reads it again once there is
			// something to read it against.
			if (config.model) observeModel(config.model);
			// The catalogue is a read of the initialize response the SDK already cached, so it
			// costs no model turn — but it is still a promise, and the frames above must not wait
			// behind it. Published as soon as it resolves instead.
			publishCatalogue();
			break;
		case "command":
			handleCommand(frame);
			break;
		case "shutdown":
			shutdown("host_shutdown");
			break;
		default:
			break;
	}
});

/// Maps one vendor catalogue row to Ciao's bounded shape, or drops it.
///
/// `description` is dropped deliberately: it is prose of vendor length that would dominate the
/// frame budget to say something a picker row has no space for. A row whose id or name is over
/// bound is dropped whole rather than truncated — a model id is an identifier, and half of one
/// names nothing, while a clipped display name would be offered as a choice nobody can read.
function catalogueRow(model) {
	const value = typeof model?.value === "string" ? model.value : null;
	const displayName = typeof model?.displayName === "string" ? model.displayName : null;
	if (!value || !displayName) return null;
	if (Buffer.byteLength(value, "utf8") > MAX_MODEL_ID_BYTES) return null;
	// Same grammar mirror as `observeModel`: a row the daemon would refuse is dropped whole
	// here, where the drop costs one picker row rather than the connection.
	if (!MODEL_ID_GRAMMAR.test(value)) return null;
	if (Buffer.byteLength(displayName, "utf8") > MAX_MODEL_DISPLAY_NAME_BYTES) return null;
	const levels = Array.isArray(model.supportedEffortLevels)
		? model.supportedEffortLevels.filter((level) => EFFORT_LEVELS.has(level))
		: [];
	return {
		value,
		display_name: displayName,
		supports_effort: model.supportsEffort === true,
		supported_effort_levels: levels.slice(0, MAX_EFFORT_LEVELS_PER_MODEL),
	};
}

/// Publishes what this account can actually run, once.
///
/// The list is the vendor's, so nothing here decides which models exist — only which of them
/// fit inside a frame Ciao is willing to carry. A failure is silent on purpose: not knowing the
/// catalogue costs the phone its picker, which is a missing control rather than a broken
/// session, and the session itself keeps working on whatever model it is already using.
function publishCatalogue() {
	if (typeof query.supportedModels !== "function") return;
	query.supportedModels().then(
		(models) => {
			if (!Array.isArray(models)) return;
			catalogue = models
				.map(catalogueRow)
				.filter((row) => row !== null)
				.slice(0, MAX_CATALOGUE_ENTRIES);
			modelResolutions.clear();
			for (const model of models) {
				if (typeof model?.resolvedModel !== "string" || typeof model?.value !== "string") continue;
				if (!catalogue.some((row) => row.value === model.value)) continue;
				modelResolutions.set(model.value, model.resolvedModel);
			}
			if (catalogue.length > 0) writeFrame({ type: "model_catalogue", models: catalogue });
			// A model seen before the catalogue landed was reported in whatever form named it,
			// because there was nothing yet to read it against. Read it again now there is. This
			// also settles the frame order the phone resolves display names in: whenever the two
			// disagree, the catalogue is on the wire before the id that needs it.
			if (activeModel) {
				const canonical = canonicalModel(activeModel);
				if (canonical !== activeModel) {
					activeModel = canonical;
					writeFrame({ type: "model", model: canonical });
				}
			}
		},
		() => {},
	);
}

/// The catalogue id for a model the vendor named, or the name itself when no row stands for it.
///
/// The vendor uses two forms and Ciao may only carry one. A row's `value` is what `setModel`
/// accepts and what the picker tags its rows with — `sonnet`, `default`, `opus[1m]` — while every
/// model the SDK *reports* is the resolved wire id behind it: `claude-sonnet-5`,
/// `claude-opus-5[1m]`. The two overlap almost nowhere, so reporting what was named put an id on
/// the wire that matched no row, and the phone's bar had nothing to name it with.
///
/// An id no row resolves to is returned as it came. That is the honest answer rather than the
/// pretty one: a model outside the catalogue is exactly the case worth seeing, and the grammar
/// check above this is what keeps the genuinely unreportable out.
function canonicalModel(model) {
	if (catalogue.some((row) => row.value === model)) return model;
	return rowResolvingTo(model, false) ?? rowResolvingTo(model, true) ?? model;
}

/// A wire id without its context-window suffix. `claude-opus-5[1m]` and `claude-opus-5` are one
/// model addressed at two sizes, and the vendor uses both names for the same session: against the
/// live SDK, `system/init` says `claude-opus-5[1m]` and the message that answers says
/// `claude-opus-5`, while the rows covering it resolve only to the bracketed form.
function baseModelID(model) {
	const bracket = model.indexOf("[");
	return bracket === -1 ? model : model.slice(0, bracket);
}

/// The catalogue id whose row stands for this wire id, or null.
///
/// Run twice: once reading ids exactly, and only if that finds nothing, once with the
/// context-window suffix dropped. The order is the whole safety of it — an account publishing both
/// windows as their own rows answers exactly and never reaches the loose pass, so the narrow
/// window is never read as the wide one.
function rowResolvingTo(model, loose) {
	const wanted = loose ? baseModelID(model) : model;
	const resolutionOf = (value) => {
		const resolved = modelResolutions.get(value);
		if (resolved === undefined) return undefined;
		return loose ? baseModelID(resolved) : resolved;
	};
	// A model already standing keeps the tie. Two rows can resolve to one wire id — the vendor
	// ships `default` and `opus[1m]` both standing for `claude-opus-5[1m]` — so without this,
	// picking "Opus (1M context)" would redraw itself as "Default (recommended)" the instant the
	// model answered, which reads as Ciao undoing the choice.
	if (activeModel && resolutionOf(activeModel) === wanted) return activeModel;
	// Otherwise the vendor's own order decides, which puts `default` ahead of the explicit row it
	// duplicates. With nothing picked that is the truer of the two: nobody chose Opus, the session
	// is running the default and should say so.
	for (const row of catalogue) {
		if (resolutionOf(row.value) === wanted) return row.value;
	}
	return null;
}

/// The model this session is running, which is the only model worth reporting.
///
/// Called with what the SDK named rather than with what was requested: a request can be
/// downgraded, ignored, or overridden at the vendor's end, and the phone must show what is
/// answering rather than what was asked for. Idempotent on the canonical form, so a steady
/// conversation emits one frame and not one per message.
function observeModel(model) {
	if (typeof model !== "string") return;
	if (Buffer.byteLength(model, "utf8") > MAX_MODEL_ID_BYTES) return;
	// "<synthetic>" and anything else outside the id grammar stays unreported: it is not what
	// is answering, and the daemon would refuse the frame at the cost of the session. Checked
	// before the catalogue is consulted, so an artifact never reaches the lookup at all.
	if (!MODEL_ID_GRAMMAR.test(model)) return;
	const canonical = canonicalModel(model);
	if (canonical === activeModel) return;
	activeModel = canonical;
	writeFrame({ type: "model", model: canonical });
}

/// The effort that was actually applied to a turn, as the SDK reported it on a hook — after any
/// silent downgrade for the chosen model. That is why this is read from the hook rather than
/// assumed from the last accepted request.
function observeEffort(effort) {
	if (typeof effort !== "string" || effort === activeEffort) return;
	if (!EFFORT_LEVELS.has(effort)) return;
	activeEffort = effort;
	writeFrame({ type: "effort", effort });
}

/// The row the active model occupies in the catalogue.
///
/// A plain lookup, because `observeModel` already resolved the two vendor forms down to the one
/// the catalogue is keyed on. A model with no row here is a model outside the catalogue, which is
/// the only case this may answer nothing for.
function activeCatalogueRow() {
	if (!activeModel) return null;
	return catalogue.find((row) => row.value === activeModel) ?? null;
}

function handleCommand(frame) {
	const commandID = frame.command_id;
	if (frame.kind === "prompt") {
		const uuid = crypto.randomUUID();
		promptsAwaitingReplay.set(uuid, commandID);
		input.push({
			type: "user",
			uuid,
			parent_tool_use_id: null,
			message: { role: "user", content: [{ type: "text", text: frame.text }] },
		});
		receipt(commandID, "accepted");
		return;
	}
	if (frame.kind === "set_permission_mode") {
		const mode = frame.mode;
		// The host validates against the SDK's union before sending; this is the second gate,
		// so a worker can never be talked into a mode by a malformed frame.
		if (!PERMISSION_MODES.has(mode)) {
			receipt(commandID, "rejected", undefined, "unsupported_permission_mode");
			return;
		}
		query.setPermissionMode(mode).then(
			() => {
				permissionMode = mode;
				receipt(commandID, "applied", "permission_mode_set");
				// Reported after the SDK accepted it, never before: the frame is a statement
				// about what the session is, not about what was requested.
				writeFrame({ type: "permission_mode", mode });
			},
			() => receipt(commandID, "outcome_unknown", undefined, "permission_mode_failed"),
		);
		return;
	}
	if (frame.kind === "set_model") {
		const model = frame.model;
		// Checked against the catalogue the SDK itself published, not against a list compiled in
		// here. That is the whole point of publishing one: the set of models this account can run
		// is the vendor's fact, and it changes without Ciao shipping.
		if (catalogue.length === 0) {
			receipt(commandID, "rejected", undefined, "model_catalogue_unavailable");
			return;
		}
		if (!catalogue.some((row) => row.value === model)) {
			receipt(commandID, "rejected", undefined, "unsupported_model");
			return;
		}
		query.setModel(model).then(
			() => {
				receipt(commandID, "applied", "model_set");
				// Reported after the SDK accepted it, never before. The next assistant message
				// re-reports whatever actually answered, so a vendor override corrects this
				// rather than leaving the phone wrong.
				observeModel(model);
			},
			() => receipt(commandID, "outcome_unknown", undefined, "model_failed"),
		);
		return;
	}
	if (frame.kind === "set_effort") {
		const effort = frame.effort;
		if (!EFFORT_LEVELS.has(effort)) {
			receipt(commandID, "rejected", undefined, "unsupported_effort");
			return;
		}
		// Checked against the *active model's* own levels, not just the union. The SDK silently
		// downgrades a level the chosen model cannot do, which would leave the phone showing an
		// effort the session is not running at — a lie that no error would ever correct. Refusing
		// categorically is the honest half of that trade.
		const row = activeCatalogueRow();
		if (!row) {
			receipt(commandID, "rejected", undefined, "model_unknown");
			return;
		}
		if (!row.supports_effort || !row.supported_effort_levels.includes(effort)) {
			receipt(commandID, "rejected", undefined, "unsupported_effort");
			return;
		}
		// There is no `setEffort`. Effort moves through the flag-settings layer, whose successive
		// calls shallow-merge top-level keys — sending this one scalar key therefore replaces only
		// it and disturbs nothing else Ciao has set.
		query.applyFlagSettings({ effortLevel: effort }).then(
			() => {
				receipt(commandID, "applied", "effort_set");
				observeEffort(effort);
			},
			() => receipt(commandID, "outcome_unknown", undefined, "effort_failed"),
		);
		return;
	}
	if (frame.kind === "interrupt") {
		query.interrupt().then(
			() => receipt(commandID, "applied", "interrupt_receipt"),
			() => receipt(commandID, "outcome_unknown", undefined, "interrupt_failed"),
		);
		return;
	}
	if (frame.kind === "interaction_response") {
		const pending = pendingInteractions.get(frame.interaction_id);
		if (!pending) {
			// Exactly-once resolution: a late or duplicate response is rejected
			// rather than re-applied to a resolved callback.
			receipt(commandID, "rejected", undefined, "already_resolved");
			return;
		}
		// A permission answered with question answers, or the reverse, is refused: the request
		// stays pending and the phone is told, rather than the worker inventing a decision.
		const decision = pending.decide(frame);
		if (!decision) {
			receipt(commandID, "rejected", undefined, "answer_shape_mismatch");
			return;
		}
		pending.settle(decision.result, "applied");
		receipt(commandID, "applied", decision.evidence);
		return;
	}
	receipt(commandID, "rejected", undefined, "unsupported_command");
}

// ---------------------------------------------------------------- stream

const heartbeat = setInterval(() => writeFrame({ type: "heartbeat" }), HEARTBEAT_MS);

function shutdown(reasonCode) {
	clearInterval(heartbeat);
	writeFrame({ type: "session_end" });
	input.close();
	socket.end();
	// A reason code is categorical; never log prompt or model content.
	process.stderr.write(`ciao-managed-worker: ${reasonCode}\n`);
	process.exit(0);
}

const TYPED = new Set(["system", "user", "assistant", "result", "stream_event"]);

/// Spec 017 §4.2: the SDK's message union is a documented closed set (TYPED above), so a sixth
/// type is the service or SDK growing under the exact pin — drift by definition, reported to
/// the daemon's ledger as a name, never content. Deduplicated and hard-capped for the worker's
/// lifetime; sent only from the stream loop, which runs strictly after the resume snapshot, so
/// a frame type this build's daemon always knows never lands inside a snapshot window.
///
/// GAP(drift): unknown *content block* types and unmapped history shapes stay untallied — at
/// this pin real transcripts contain block machinery the worker deliberately cards as
/// unsupported, and separating novel from known-at-pin needs a grounded block-type list from
/// the managed probes, not a guess here.
const reportedDrift = new Set();
const MAX_DRIFT_REPORTS = 8;
function reportDrift(surface, name) {
	const bounded = String(name).slice(0, 48);
	const key = `${surface} ${bounded}`;
	if (reportedDrift.has(key) || reportedDrift.size >= MAX_DRIFT_REPORTS) return;
	reportedDrift.add(key);
	writeFrame({ type: "drift_note", surface, name: bounded });
}
let assistantSequence = 0;
/// The message the partials currently belong to, from the stream's own `message_start`.
let streamingMessageID = null;
let reportedVendorSession = null;

// The only place that knows a turn is under way. The SDK brackets one cleanly — the replay echo
// of a prompt opens it, the result message closes it — so Ciao reports those two edges rather
// than inferring activity from output or elapsed time. `activity` is a bounded token, not copy:
// the phone decides what word to show.
let runSequence = 0;
let openRunID = null;
let openActivity = null;

function turnRunning(activity) {
	runSequence += 1;
	openRunID = `run-${runSequence}`;
	openActivity = activity;
	writeFrame({ type: "turn", state: "running", run_id: openRunID, activity });
}

/// What the open run is doing *now*, on the run it is already reporting.
///
/// Every word sent from here restates something the SDK reported about itself in the message
/// that triggered it — a thinking delta, a text delta, a tool call. None is derived from timing,
/// from silence, or from what usually happens next. `working` is the word for a turn that is in
/// flight and has said nothing finer, which is the one claim the bridge is entitled to make on
/// its own; it is not a guess that the model is busy in some particular way.
///
/// Same run ID on purpose: this narrows a turn already in progress. Minting a new one would
/// claim the turn ended and another began.
function turnActivity(activity) {
	if (!openRunID || activity === openActivity) return;
	openActivity = activity;
	writeFrame({ type: "turn", state: "running", run_id: openRunID, activity });
}

function turnCompleted() {
	// Idempotent: a result with no open run still says the session is not working, which is the
	// claim that matters after a resume or an interrupt.
	writeFrame({ type: "turn", state: "completed", run_id: openRunID ?? undefined });
	openRunID = null;
	openActivity = null;
}

try {
	for await (const message of query) {
		if (!TYPED.has(message.type)) {
			reportDrift("sdk_stream", message.type);
			continue;
		}
		if (message.type === "system" && message.subtype === "init") {
			// The SDK is lazy: no session identity exists until the first turn
			// begins. Report it the moment it does, which is what makes this
			// session resumable and ownership-checkable.
			if (typeof message.session_id === "string" && message.session_id !== reportedVendorSession) {
				reportedVendorSession = message.session_id;
				writeFrame({ type: "vendor_session", vendor_session_id: message.session_id });
			}
			// The same message names the model the turn is starting on, and it names it before the
			// model has produced a word — the earliest this worker can state it truthfully. The
			// assistant message below re-reports whatever actually answered, which is what
			// survives a downgrade or an override.
			observeModel(message.model);
		}
		if (message.type === "user" && message.isReplay === true) {
			// The replay echo is the delivery acknowledgement.
			const commandID = promptsAwaitingReplay.get(message.uuid);
			if (commandID) {
				promptsAwaitingReplay.delete(message.uuid);
				receipt(commandID, "applied", "replay_correlated");
			}
			const text = textFromContent(message.message?.content);
			// Machinery delivered through the prompt path. It is not a message and it does not
			// open a turn: minting a run for a background job finishing would claim the previous
			// turn ended, mid-turn, once per notification.
			if (isSyntheticPrompt(text)) continue;
			if (text) {
				sendEntry("upsert_entry", sourceID("user", message.uuid), "user_message", textBody(text));
			}
			// The prompt was delivered and a turn is in flight. That is all this knows: nothing
			// has reported thinking, and saying so here was a guess that then sat on screen for
			// the length of the turn.
			turnRunning("working");
			continue;
		}
		if (message.type === "user") {
			// Tool results arrive as user-role blocks.
			const content = message.message?.content;
			if (Array.isArray(content)) {
				for (const block of content) {
					if (block?.type !== "tool_result") continue;
					// The call came back. What happens next is not knowable from here, so the
					// turn drops to the bare claim that it is still running.
					turnActivity("working");
					sendEntry(
						"upsert_entry",
						sourceID("tool", block.tool_use_id),
						"tool",
						toolBody(
							"tool",
							block.is_error === true ? "failed" : "complete",
							undefined,
							textFromContent(block.content),
						),
					);
				}
			}
			continue;
		}
		if (message.type === "stream_event") {
			// Partial assistant text, which is the only thing that makes a reply arrive as it is
			// written rather than all at once when the turn ends. The SDK hands over Anthropic's
			// raw streaming events; everything except a text delta on the message being written
			// is dropped, including a tool call's streamed input — a tool row prints its bounded
			// argument preview when the call is announced, not one character at a time.
			//
			// Keyed on the message's own id so the completed `assistant` message below lands on
			// the same entry and replaces the accumulation with the authoritative text. Any
			// other key would draw the reply twice.
			const event = message.event;
			if (event?.type === "message_start" && typeof event.message?.id === "string") {
				streamingMessageID = event.message.id;
			}
			// Extended thinking arrives as its own content block. This is the only place the
			// worker is entitled to say the model is thinking: it is thinking out loud and the
			// SDK is handing over the words. A pin or a request without extended thinking emits
			// none of these, and then the turn simply never claims to be thinking.
			if (event?.type === "content_block_delta" && event.delta?.type === "thinking_delta") {
				turnActivity("thinking");
			}
			if (
				streamingMessageID &&
				event?.type === "content_block_delta" &&
				event.delta?.type === "text_delta" &&
				typeof event.delta.text === "string" &&
				event.delta.text.length > 0
			) {
				// The reply is arriving, as text, right now.
				turnActivity("responding");
				appendText(sourceID("assistant", streamingMessageID), "assistant_message", event.delta.text);
			}
			continue;
		}
		if (message.type === "assistant") {
			// The one authoritative statement of which model is answering. It is on the message the
			// model produced, so it survives an override, a downgrade, or a fallback that no
			// request-side bookkeeping would ever see.
			observeModel(message.message?.model);
			const content = message.message?.content;
			const text = textFromContent(content);
			if (text) {
				assistantSequence += 1;
				sendEntry(
					"upsert_entry",
					// `message.message.id` first, because that is what the partials above were
					// keyed on. `uuid` remains the fallback for a pin that omits it, at the cost
					// of the streamed copy staying beside the finished one.
					sourceID("assistant", message.message?.id ?? message.uuid ?? assistantSequence),
					"assistant_message",
					textBody(text),
				);
			}
			if (Array.isArray(content)) {
				for (const block of content) {
					if (block?.type !== "tool_use") continue;
					// A call was made, so the turn is doing rather than saying.
					turnActivity("working");
					sendEntry(
						"upsert_entry",
						sourceID("tool", block.id),
						"tool",
						toolBody(safeToolName(block.name), "running", JSON.stringify(block.input ?? {})),
					);
				}
			}
			continue;
		}
		if (message.type === "result") {
			// Every prompt still awaiting a replay after a turn ended is ambiguous.
			for (const [uuid, commandID] of promptsAwaitingReplay) {
				promptsAwaitingReplay.delete(uuid);
				receipt(commandID, "outcome_unknown", undefined, "turn_ended");
			}
			turnCompleted();
		}
	}
	shutdown("stream_complete");
} catch {
	// Grounded: the CLI exits nonzero after an interrupted or errored turn and
	// the SDK surfaces it as a throw even when the result was delivered.
	shutdown("stream_ended");
}
