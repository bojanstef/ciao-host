import { afterEach, expect, test } from "bun:test";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

// The worker is a top-level-await script that connects to its socket on import, so it cannot be
// imported and poked at. It is run the way the daemon runs it — a real subprocess, a real framed
// Unix socket, and a fake SDK planted where the launcher would have put the real one. That also
// means this exercises the actual file the launcher digests, not a testable copy of it.

const WORKER = path.join(import.meta.dir, "worker.mjs");
const SESSION_ID = "0123456789abcdef0123456789abcdef";

const resources: Array<() => void | Promise<void>> = [];
afterEach(async () => {
	while (resources.length > 0) await resources.pop()?.();
});

function decodeFrames(onValue: (value: Record<string, unknown>) => void) {
	let buffer = Buffer.alloc(0);
	return (chunk: Buffer) => {
		buffer = Buffer.concat([buffer, chunk]);
		while (buffer.length >= 4) {
			const length = buffer.readUInt32BE(0);
			if (buffer.length < length + 4) return;
			onValue(JSON.parse(buffer.subarray(4, length + 4).toString("utf8")));
			buffer = buffer.subarray(length + 4);
		}
	};
}

function encodeFrame(value: unknown): Buffer {
	const body = Buffer.from(JSON.stringify(value), "utf8");
	const frame = Buffer.allocUnsafe(body.length + 4);
	frame.writeUInt32BE(body.length, 0);
	body.copy(frame, 4);
	return frame;
}

async function eventually(predicate: () => boolean, timeout = 5_000): Promise<void> {
	const deadline = Date.now() + timeout;
	while (!predicate()) {
		if (Date.now() >= deadline) throw new Error("timed_out");
		await Bun.sleep(20);
	}
}

/// A stand-in for the pinned Agent SDK that replays one scripted turn. Only the shapes the worker
/// actually reads are provided; anything else it touched would be a boundary violation.
///
/// The permission half models the whole documented sequence, because that is what the feature
/// under test depends on: the callback decides, the tool then runs headlessly and reports that
/// nothing was chosen, and any registered PostToolUse hook may replace that output before the
/// model is handed it.
type HistoryFixture = {
	sessionID: string;
	fileSize: number;
	createdAt?: number;
	messages: unknown[];
};

function plantFakeSdk(
	root: string,
	script: unknown[],
	permission?: { tool: string; input: unknown },
	history?: HistoryFixture,
	models?: unknown[],
	hold?: boolean,
): void {
	const dir = path.join(root, "node_modules", "@anthropic-ai", "claude-agent-sdk");
	fs.mkdirSync(dir, { recursive: true });
	fs.writeFileSync(
		path.join(dir, "sdk.mjs"),
		`import fs from "node:fs";
import path from "node:path";
const SCRIPT = ${JSON.stringify(script)};
const PERMISSION = ${JSON.stringify(permission ?? null)};
const HISTORY = ${JSON.stringify(history ?? null)};
const MODELS = ${JSON.stringify(models ?? null)};
const HOLD = ${JSON.stringify(hold ?? false)};
const TOOL_USE_ID = "toolu_synthetic";
// The fake records what the worker asked of the SDK, because several of these behaviours are
// only observable as a call that did or did not happen with a particular argument.
const JOURNAL = path.join(import.meta.dirname, "journal.json");
const journal = { options: null, setModel: [], flagSettings: [] };
function record() {
	try { fs.writeFileSync(JOURNAL, JSON.stringify(journal)); } catch {}
}
export async function getSessionInfo(sessionID) {
	if (!HISTORY || sessionID !== HISTORY.sessionID) return undefined;
	return {
		sessionId: sessionID,
		summary: "Synthetic history",
		lastModified: 1,
		fileSize: HISTORY.fileSize,
		createdAt: HISTORY.createdAt,
	};
}
export async function getSessionMessages(sessionID) {
	return HISTORY && sessionID === HISTORY.sessionID ? HISTORY.messages : [];
}
export function query(config) {
	journal.options = {
		model: config.options.model ?? null,
		permissionMode: config.options.permissionMode ?? null,
	};
	record();
	return {
		async *[Symbol.asyncIterator]() {
			// Let registration settle first, so the frame order under test is the real one.
			await new Promise((resolve) => setTimeout(resolve, 150));
			if (PERMISSION) {
				// Exactly how the real SDK raises one: the tool name and its arguments, handed to
				// the callback the worker supplied.
				const decision = await config.options.canUseTool(PERMISSION.tool, PERMISSION.input, {
					signal: new AbortController().signal,
					suggestions: [],
					toolUseID: TOOL_USE_ID,
				});
				let output = "The user did not answer the questions.";
				if (decision && decision.behavior === "allow") {
					for (const matcher of (config.options.hooks && config.options.hooks.PostToolUse) || []) {
						for (const hook of matcher.hooks) {
							const result = await hook({
								hook_event_name: "PostToolUse",
								tool_name: PERMISSION.tool,
								tool_input: PERMISSION.input,
								tool_response: output,
								tool_use_id: TOOL_USE_ID,
							});
							const replacement =
								result && result.hookSpecificOutput && result.hookSpecificOutput.updatedToolOutput;
							if (replacement !== undefined) output = replacement;
						}
					}
				} else {
					output = "Denied.";
				}
				// The tool result the model is handed, which is the only thing that decides whether
				// the answers actually reached it.
				yield {
					type: "user",
					message: {
						content: [
							{
								type: "tool_result",
								tool_use_id: TOOL_USE_ID,
								content: [
									{ type: "text", text: typeof output === "string" ? output : JSON.stringify(output) },
								],
							},
						],
					},
				};
			}
			for (const message of SCRIPT) {
				yield message;
				await new Promise((resolve) => setTimeout(resolve, 10));
			}
			// A real session sits waiting for the next prompt rather than ending the moment it
			// stops talking. Command tests need that window; the harness kills the child after.
			if (HOLD) await new Promise(() => {});
		},
		interrupt() {},
		setPermissionMode() {},
		// Async on purpose: the real surfaces return promises and the worker chains a receipt
		// off each one, so a synchronous fake would pass a test the real SDK would fail.
		async setModel(model) {
			journal.setModel.push(model ?? null);
			record();
		},
		async applyFlagSettings(settings) {
			journal.flagSettings.push(settings);
			record();
		},
		// A read of the cached initialize response in the real SDK, so it costs no model turn.
		// A thrown call stands for a pin that does not offer the surface at all.
		async supportedModels() {
			if (MODELS === null) throw new Error("unsupported");
			return MODELS;
		},
	};
}
`,
	);
}

type Harness = {
	frames: Record<string, unknown>[];
	send: (value: unknown) => void;
	child: ReturnType<typeof Bun.spawn>;
	/// Drops the daemon side of the bridge the way the real daemon does on a refused frame: the
	/// connection's task ends and the fd closes, with nothing else said.
	dropPeer: () => void;
	/// What the worker actually asked of the SDK. Several of these behaviours are only
	/// observable as a call that did or did not happen with a particular argument.
	journal: () => { options: any; setModel: unknown[]; flagSettings: unknown[] };
};

/// One worker, run the way the daemon runs it, with the socket left open so a test can answer
/// what the worker raises.
async function startWorker(
	script: unknown[],
	permission?: { tool: string; input: unknown },
	history?: HistoryFixture,
	models?: unknown[],
	extraEnv?: Record<string, string>,
	hold?: boolean,
): Promise<Harness> {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "ciao-managed-worker-"));
	const socketPath = path.join(root, "agent.sock");
	const frames: Record<string, unknown>[] = [];
	let peer: net.Socket | undefined;

	const server = net.createServer((socket) => {
		peer = socket;
		socket.on(
			"data",
			decodeFrames((frame) => {
				frames.push(frame);
				if (frame.type === "register") {
					socket.write(
						encodeFrame({
							v: 1,
							type: "registered",
							session_id: SESSION_ID,
							process_generation: 1,
							snapshot_epoch: 1,
						}),
					);
				}
			}),
		);
	});
	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(socketPath, resolve);
	});

	plantFakeSdk(root, script, permission, history, models, hold);

	const child = Bun.spawn([process.execPath, WORKER], {
		env: {
			...process.env,
			CIAO_MANAGED_SOCKET: socketPath,
			CIAO_MANAGED_SDK_PREFIX: root,
			CIAO_MANAGED_SESSION_ID: SESSION_ID,
			CIAO_MANAGED_SPAWN_TOKEN: "fedcba9876543210fedcba9876543210",
			CIAO_MANAGED_WORKSPACE_LABEL: "workspace",
			CIAO_MANAGED_CLI_VERSION: "2.1.233",
			CIAO_MANAGED_SDK_VERSION: "0.3.233",
			...(history ? { CIAO_MANAGED_RESUME_SESSION_ID: history.sessionID } : {}),
			...(extraEnv ?? {}),
		},
		stdout: "pipe",
		stderr: "pipe",
	});
	resources.push(async () => {
		child.kill();
		peer?.destroy();
		await new Promise<void>((resolve) => server.close(() => resolve()));
		fs.rmSync(root, { recursive: true, force: true });
	});

	const journalPath = path.join(
		root,
		"node_modules",
		"@anthropic-ai",
		"claude-agent-sdk",
		"journal.json",
	);
	return {
		frames,
		send: (value) => peer?.write(encodeFrame(value)),
		child,
		dropPeer: () => peer?.destroy(),
		journal: () => {
			try {
				return JSON.parse(fs.readFileSync(journalPath, "utf8"));
			} catch {
				return { options: null, setModel: [], flagSettings: [] };
			}
		},
	};
}

test("a resumed worker snapshots bounded history before any live event", async () => {
	const history: HistoryFixture = {
		sessionID: "11111111-2222-4333-8444-555555555555",
		fileSize: 16_384,
		createdAt: 1_700_000_000_000,
		messages: [
			{
				type: "user",
				uuid: "user-old",
				timestamp: "2023-11-14T22:13:20.000Z",
				message: { role: "user", content: "Earlier synthetic question." },
			},
			{
				type: "assistant",
				uuid: "assistant-old",
				timestamp: "2023-11-14T22:13:21.000Z",
				message: {
					role: "assistant",
					id: "message-old",
					content: [
						{ type: "thinking", thinking: "Omitted reasoning." },
						{ type: "redacted_thinking", data: "Redacted reasoning marker." },
						{ type: "text", text: "Earlier synthetic answer." },
						{ type: "tool_use", id: "tool-old", name: "Read", input: { file_path: "fixture" } },
					],
				},
			},
			{
				type: "user",
				uuid: "tool-result-old",
				timestamp: "2023-11-14T22:13:22.000Z",
				message: {
					role: "user",
					content: [
						{
							type: "tool_result",
							tool_use_id: "tool-old",
							content: [{ type: "text", text: "Synthetic result." }],
						},
						{ type: "image", source: { type: "base64", data: "not-forwarded" } },
					],
				},
			},
		],
	};
	const { frames } = await startWorker(
		[
			{
				type: "assistant",
				uuid: "assistant-race",
				message: {
					id: "message-old",
					content: [{ type: "text", text: "Live authoritative replacement." }],
				},
			},
		],
		undefined,
		history,
	);
	await eventually(() => frames.some((frame) => frame.type === "snapshot_end"));
	await eventually(() =>
		frames.some(
			(frame) => frame.type === "upsert_entry" && (frame as any).entry.kind === "assistant_message",
		),
	);

	const registration = frames.find((frame) => frame.type === "register") as Record<string, any>;
	expect(registration.resumed).toBe(true);
	expect(registration.history_complete).toBe(true);

	const entries = frames
		.filter((frame) => frame.type === "snapshot_entry")
		.map((frame) => (frame as any).entry);
	expect(entries.map((entry) => entry.kind)).toEqual([
		"user_message",
		"assistant_message",
		"tool",
		"unsupported",
	]);
	expect(entries.map((entry) => entry.source_id)).toEqual([
		"user-user-old",
		"assistant-message-old",
		"tool-tool-old",
		"unsupported-tool-result-old-1",
	]);
	expect(entries[0].timestamp).toBe(1_700_000_000);
	expect(entries[1].body.text).toBe("Earlier synthetic answer.");
	expect(JSON.stringify(entries)).not.toContain("Omitted reasoning");
	expect(JSON.stringify(entries)).not.toContain("Redacted reasoning marker");
	expect(entries[2].source_revision).toBe(2);
	expect(entries[2].body.tool).toMatchObject({
		name: "Read",
		status: "complete",
		result_preview: "Synthetic result.",
	});
	expect(entries[3].body).toEqual({
		type: "unsupported",
		reason_code: "claude_history_content",
	});
	expect(JSON.stringify(entries)).not.toContain("not-forwarded");

	const snapshotEnd = frames.findIndex((frame) => frame.type === "snapshot_end");
	const liveIndex = frames.findIndex(
		(frame) => frame.type === "upsert_entry" && (frame as any).entry.kind === "assistant_message",
	);
	const live = frames[liveIndex] as any;
	// History and the live stream name one upstream object identically. The seeded revision makes
	// the live copy replace the historical row, and the snapshot always arrives first.
	expect(liveIndex).toBeGreaterThan(snapshotEnd);
	expect(live.entry.source_id).toBe("assistant-message-old");
	expect(live.entry.source_revision).toBe(2);
});

test("a transcript above the reader bound stays marked as earlier Claude history", async () => {
	const history: HistoryFixture = {
		sessionID: "11111111-2222-4333-8444-555555555555",
		fileSize: 4 * 1024 * 1024 + 1,
		messages: [
			{
				type: "user",
				uuid: "must-not-be-read",
				message: { role: "user", content: "Synthetic over-bound content." },
			},
		],
	};
	const { frames } = await startWorker([], undefined, history);
	await eventually(() => frames.some((frame) => frame.type === "snapshot_end"));
	const registration = frames.find((frame) => frame.type === "register") as Record<string, any>;
	expect(registration.resumed).toBe(true);
	expect(registration.history_complete).toBe(false);
	expect(frames.filter((frame) => frame.type === "snapshot_entry")).toHaveLength(0);
});

test("JSON expansion cannot silently overflow or punch a hole in history frames", async () => {
	const history: HistoryFixture = {
		sessionID: "11111111-2222-4333-8444-555555555555",
		fileSize: 32 * 1024,
		messages: [
			{
				type: "user",
				uuid: "before-escaped-frame",
				message: { role: "user", content: "Older safe entry." },
			},
			{
				type: "user",
				uuid: "escaped-frame",
				// Raw bytes fit the text bound, but each control character needs six JSON bytes.
				message: { role: "user", content: "\u0000".repeat(16 * 1024) },
			},
			{
				type: "user",
				uuid: "after-escaped-frame",
				message: { role: "user", content: "Newest safe entry." },
			},
		],
	};
	const { frames } = await startWorker([], undefined, history);
	await eventually(() => frames.some((frame) => frame.type === "snapshot_end"));

	const registration = frames.find((frame) => frame.type === "register") as Record<string, any>;
	expect(registration.history_complete).toBe(false);
	const entries = frames
		.filter((frame) => frame.type === "snapshot_entry")
		.map((frame) => (frame as any).entry);
	// The fallback is a contiguous newest tail, so the boundary stays truthful rather than
	// pretending an omitted middle row was merely older than everything visible.
	expect(entries.map((entry) => entry.source_id)).toEqual(["user-after-escaped-frame"]);
	expect(entries[0].body.text).toBe("Newest safe entry.");
});

test(
	"history keeps the newest 4096 entries and withdraws full coverage at limit plus one",
	async () => {
		const history: HistoryFixture = {
			sessionID: "11111111-2222-4333-8444-555555555555",
			// Exactly at the input limit: this must be read. The independent canonical count
			// limit below is what makes the result incomplete.
			fileSize: 4 * 1024 * 1024,
			messages: Array.from({ length: 4_097 }, (_, index) => ({
				type: "user",
				uuid: `history-user-${index}`,
				message: { role: "user", content: `Synthetic history ${index}.` },
			})),
		};
		const { frames } = await startWorker([], undefined, history);
		await eventually(() => frames.some((frame) => frame.type === "snapshot_end"), 15_000);

		const registration = frames.find((frame) => frame.type === "register") as Record<string, any>;
		expect(registration.history_complete).toBe(false);
		const entries = frames
			.filter((frame) => frame.type === "snapshot_entry")
			.map((frame) => (frame as any).entry);
		expect(entries).toHaveLength(4_096);
		expect(entries[0].source_id).toBe("user-history-user-1");
		expect(entries.at(-1).source_id).toBe("user-history-user-4096");
	},
	20_000,
);

test("canonical history keeps its newest entries inside the independent byte bound", async () => {
	const largeText = "x".repeat(16 * 1024);
	const history: HistoryFixture = {
		sessionID: "11111111-2222-4333-8444-555555555555",
		// Hold the reader at its accepted input edge. This synthetic SDK deliberately returns a
		// larger decoded shape so this test isolates the independent canonical-output fence.
		fileSize: 4 * 1024 * 1024,
		messages: Array.from({ length: 260 }, (_, index) => ({
			type: "user",
			uuid: `byte-bound-user-${index}`,
			message: { role: "user", content: `${index}:${largeText}` },
		})),
	};
	const { frames } = await startWorker([], undefined, history);
	await eventually(() => frames.some((frame) => frame.type === "snapshot_end"), 15_000);

	const registration = frames.find((frame) => frame.type === "register") as Record<string, any>;
	expect(registration.history_complete).toBe(false);
	const entries = frames
		.filter((frame) => frame.type === "snapshot_entry")
		.map((frame) => (frame as any).entry);
	const encodedBytes = entries.reduce(
		(total, entry) => total + Buffer.byteLength(JSON.stringify(entry)),
		0,
	);
	expect(entries.length).toBeLessThan(260);
	expect(encodedBytes).toBeLessThanOrEqual(4 * 1024 * 1024);
	expect(entries[0].source_id).not.toBe("user-byte-bound-user-0");
	expect(entries.at(-1).source_id).toBe("user-byte-bound-user-259");
});

test("a message type outside the SDK's union is reported as drift, once, and skipped", async () => {
	const { frames } = await startWorker([
		{ type: "user", isReplay: true, uuid: "u1", message: { content: "hello" } },
		// The SDK's message union is a documented closed set; a sixth type is the service or
		// SDK growing under the exact pin. Twice, to prove the report deduplicates.
		{ type: "telemetryBurst", payload: { secret: "never leaves the worker" } },
		{ type: "telemetryBurst", payload: { secret: "still never" } },
		{
			type: "assistant",
			uuid: "a1",
			message: { id: "msg_1", content: [{ type: "text", text: "hi" }] },
		},
		{ type: "result", subtype: "success" },
	]);

	await eventually(() =>
		frames.some((frame) => frame.type === "turn" && frame.state === "completed"),
	);

	const drift = frames.filter((frame) => frame.type === "drift_note");
	expect(drift.length).toBe(1);
	expect(drift[0].surface).toBe("sdk_stream");
	expect(drift[0].name).toBe("telemetryBurst");
	// The name, never the payload: nothing else about the message leaves the worker.
	expect(JSON.stringify(drift[0])).not.toContain("secret");
	// And the unknown message produced no timeline entry.
	const entries = frames.filter((frame) => frame.type === "upsert_entry");
	expect(entries.some((frame) => JSON.stringify(frame).includes("telemetryBurst"))).toBe(false);
});

test("machinery replayed through the prompt path is not a message and does not open a turn", async () => {
	const { frames } = await startWorker([
		{ type: "user", isReplay: true, uuid: "u1", message: { content: "tell me a joke" } },
		// Everything Claude delivers through the prompt path itself. `--replay-user-messages`
		// replays all of it, and drawing any of it as a prompt puts raw XML in the conversation
		// as if the reader had typed it.
		{
			type: "user",
			isReplay: true,
			uuid: "u2",
			message: { content: "<task-notification>\n<task-id>abc</task-id>\n</task-notification>" },
		},
		{
			type: "user",
			isReplay: true,
			uuid: "u3",
			message: { content: "<system-reminder>be careful</system-reminder>" },
		},
		{
			type: "assistant",
			uuid: "a1",
			message: { id: "msg_1", content: [{ type: "text", text: "why did the agent cross" }] },
		},
		{ type: "result", subtype: "success" },
	]);

	await eventually(() =>
		frames.some((frame) => frame.type === "turn" && frame.state === "completed"),
	);

	const userEntries = frames.filter(
		(frame) => frame.type === "upsert_entry" && frame.entry.kind === "user_message",
	);
	expect(userEntries.length).toBe(1);
	expect(userEntries[0].entry.source_id).toBe("user-u1");

	// One turn, not three. A background job finishing must not read as a new turn starting.
	const opened = frames.filter((frame) => frame.type === "turn" && frame.state === "running");
	expect(new Set(opened.map((frame) => frame.run_id)).size).toBe(1);
});

test("a turn only names what the SDK reported, and streams into the entry it will finish", async () => {
	const { frames } = await startWorker([
		{ type: "user", isReplay: true, uuid: "u1", message: { content: "tell me a joke" } },
		{ type: "stream_event", uuid: "s1", event: { type: "message_start", message: { id: "msg_1" } } },
		{
			type: "stream_event",
			uuid: "s2",
			event: { type: "content_block_delta", delta: { type: "thinking_delta", thinking: "hmm" } },
		},
		{
			type: "stream_event",
			uuid: "s3",
			event: { type: "content_block_delta", delta: { type: "text_delta", text: "why did " } },
		},
		{
			type: "stream_event",
			uuid: "s4",
			event: { type: "content_block_delta", delta: { type: "text_delta", text: "the agent cross" } },
		},
		{
			type: "assistant",
			uuid: "a1",
			message: { id: "msg_1", content: [{ type: "text", text: "why did the agent cross" }] },
		},
		{ type: "result", subtype: "success" },
	]);

	await eventually(() =>
		frames.some((frame) => frame.type === "turn" && frame.state === "completed"),
	);
	const running = frames.filter((frame) => frame.type === "turn" && frame.state === "running");

	// Each word restates the message that produced it, in the order those arrived: a prompt is
	// only a turn in flight, a thinking delta is the sole licence to say thinking, and text
	// arriving is the sole licence to say responding.
	expect(running.map((frame) => frame.activity)).toEqual(["working", "thinking", "responding"]);
	// The second text delta changes nothing, so it says nothing.
	expect(new Set(running.map((frame) => frame.run_id)).size).toBe(1);

	// Partials append to the entry the finished message then replaces, so the reply is drawn
	// once. A different key here would leave the streamed copy beside the finished one.
	const appends = frames.filter((frame) => frame.type === "append_text");
	expect(appends.map((frame) => frame.delta.delta)).toEqual(["why did ", "the agent cross"]);
	expect(new Set(appends.map((frame) => frame.delta.source_id))).toEqual(
		new Set(["assistant-msg_1"]),
	);
	expect(appends.map((frame) => frame.delta.source_revision)).toEqual([1, 2]);
	const finished = frames.filter(
		(frame) => frame.type === "upsert_entry" && frame.entry.kind === "assistant_message",
	);
	expect(finished.map((frame) => frame.entry.source_id)).toEqual(["assistant-msg_1"]);
});

test("the worker brackets a turn with running and completed, around the content it maps", async () => {
	const { frames, child } = await startWorker([
		// The replay echo is what acknowledges delivery, and what opens the turn.
		{ type: "user", isReplay: true, uuid: "u1", message: { content: "tell me a joke" } },
		{
			type: "assistant",
			uuid: "a1",
			message: { content: [{ type: "text", text: "why did the agent cross the road" }] },
		},
		{ type: "result", subtype: "success" },
	]);

	const turns = () => frames.filter((frame) => frame.type === "turn");
	await eventually(() => turns().length >= 2);

	const [running, completed] = turns();
	expect(running.state).toBe("running");
	// A bounded token the phone maps to copy, never display text chosen by the worker. The
	// prompt opening a turn is entitled to say a turn is running and nothing more: "thinking"
	// here was a guess, and only a thinking delta may claim it.
	expect(running.activity).toBe("working");
	expect(typeof running.run_id).toBe("string");
	expect(completed.state).toBe("completed");
	// The run that ended is the run that started, so the phone can tell turns apart.
	expect(completed.run_id).toBe(running.run_id);

	// The edges bracket the turn: the prompt echo opens it and the assistant content lands
	// inside, which is what lets the phone keep the working row up while the reply arrives
	// above it.
	const order = frames.map((frame) =>
		frame.type === "turn" ? `turn:${frame.state}` : String(frame.type),
	);
	const opened = order.indexOf("turn:running");
	const closed = order.indexOf("turn:completed");
	const assistant = order.lastIndexOf("upsert_entry");
	expect(opened).toBeGreaterThan(order.indexOf("snapshot_end"));
	expect(assistant).toBeGreaterThan(opened);
	expect(closed).toBeGreaterThan(assistant);

	// Nothing categorical leaks the prompt or the reply on the process's own streams.
	child.kill();
	const stderr = await new Response(child.stderr).text();
	expect(stderr).not.toContain("joke");
	expect(stderr).not.toContain("road");
});

test("an ordinary tool is still a permission card with two host-issued choices", async () => {
	const { frames, send } = await startWorker([{ type: "result", subtype: "success" }], {
		tool: "Bash",
		input: { command: "rm -rf ~/Downloads/build" },
	});

	await eventually(() => frames.some((frame) => frame.type === "upsert_interaction"));
	const raised = frames.find((frame) => frame.type === "upsert_interaction") as Record<string, any>;
	expect(raised.interaction.kind).toBe("permission");
	expect(raised.interaction.title).toBe("Run Bash");

	// The push follows the card, so the row already shows what the notification is about.
	await eventually(() => frames.some((frame) => frame.type === "notification"));
	const pushed = frames.find((frame) => frame.type === "notification") as Record<string, any>;
	expect(pushed.kind).toBe("permission_prompt");
	expect(frames.findIndex((frame) => frame.type === "notification")).toBeGreaterThan(
		frames.findIndex((frame) => frame.type === "upsert_interaction"),
	);
	expect(raised.interaction.response_schema.type).toBe("choices");
	expect(
		raised.interaction.response_schema.choices.map((choice: { choice_id: string }) => choice.choice_id),
	).toEqual(["allow-once", "deny"]);
	expect(raised.interaction.body).toContain("rm -rf");

	// Answering it with question answers is refused rather than guessed at: the request stays
	// pending and the phone is told, which is the failure the shapes could otherwise share.
	send({
		v: 1,
		type: "command",
		command_id: "command-mismatched",
		kind: "interaction_response",
		interaction_id: raised.interaction.interaction_id,
		answers: [{ question_id: "q0", choice_ids: ["q0-o0"] }],
	});
	await eventually(() => frames.some((frame) => frame.type === "command_receipt"));
	const refused = frames.find((frame) => frame.type === "command_receipt") as Record<string, any>;
	expect(refused.state).toBe("rejected");
	expect(refused.reason_code).toBe("answer_shape_mismatch");
	expect(frames.some((frame) => frame.type === "resolve_interaction")).toBe(false);

	send({
		v: 1,
		type: "command",
		command_id: "command-allow",
		kind: "interaction_response",
		interaction_id: raised.interaction.interaction_id,
		choice_id: "allow-once",
	});
	await eventually(() => frames.some((frame) => frame.type === "resolve_interaction"));
	const applied = frames.filter((frame) => frame.type === "command_receipt").at(-1) as Record<string, any>;
	expect(applied.state).toBe("applied");
	expect(applied.evidence).toBe("permission_resolved");
});

test("an AskUserQuestion is answered from the phone, and the answers become the tool's output", async () => {
	// The real shape, from the pinned SDK's own AskUserQuestionInput: up to four questions, each
	// with a header chip, two to four options carrying a label and a description, and a
	// per-question multiSelect.
	const askUserQuestion = {
		questions: [
			{
				question: "Which transport should it use?",
				header: "Transport",
				multiSelect: false,
				options: [
					{ label: "Iroh", description: "Direct QUIC where possible." },
					{ label: "Relay only", description: "Always through the relay." },
				],
			},
			{
				question: "Which platforms should it cover?",
				header: "Platforms",
				multiSelect: true,
				options: [
					{ label: "macOS", description: "The qualified host." },
					{ label: "Linux", description: "Unaccepted." },
				],
			},
		],
	};

	const { frames, send } = await startWorker([{ type: "result", subtype: "success" }], {
		tool: "AskUserQuestion",
		input: askUserQuestion,
	});

	await eventually(() => frames.some((frame) => frame.type === "upsert_interaction"));
	const raised = frames.find((frame) => frame.type === "upsert_interaction") as Record<string, any>;
	const interaction = raised.interaction;

	// A question, not a permission: the phone is asked to answer it rather than to approve it.
	expect(interaction.kind).toBe("question");
	expect(interaction.title).toBe("Claude has 2 questions");

	// And it pushes as a question, not as a permission.
	await eventually(() => frames.some((frame) => frame.type === "notification"));
	const pushed = frames.find((frame) => frame.type === "notification") as Record<string, any>;
	expect(pushed.kind).toBe("question_prompt");
	// The body stays empty because the schema carries the prose. A permission's body is a tool's
	// bounded argument preview, and repeating the questions there would render them twice.
	expect(interaction.body).toBe("");

	const schema = interaction.response_schema;
	expect(schema.type).toBe("questions");
	expect(schema.questions).toHaveLength(2);
	expect(schema.questions[0]).toMatchObject({
		question_id: "q0",
		prompt: "Which transport should it use?",
		header: "Transport",
		// multiSelect is carried as the canonical response kind rather than a vendor boolean.
		response_kind: "single_choice",
		required: true,
	});
	expect(schema.questions[1].response_kind).toBe("multi_choice");
	// The description is what makes an option decidable; the label alone is a noun phrase.
	expect(schema.questions[0].options).toEqual([
		{ choice_id: "q0-o0", label: "Iroh", description: "Direct QUIC where possible." },
		{ choice_id: "q0-o1", label: "Relay only", description: "Always through the relay." },
	]);
	// The tool supplies an "Other" escape automatically, so the phone is given room to type one.
	expect(schema.questions[0].max_text_bytes).toBeGreaterThan(0);

	// Answer it the way the phone does: identifiers plus free text, never the agent's own labels.
	send({
		v: 1,
		type: "command",
		command_id: "command-answer",
		kind: "interaction_response",
		interaction_id: interaction.interaction_id,
		answers: [
			{ question_id: "q0", choice_ids: ["q0-o1"] },
			{ question_id: "q1", choice_ids: ["q1-o0"], text: "and FreeBSD" },
		],
	});

	await eventually(() => frames.some((frame) => frame.type === "resolve_interaction"));
	const receipt = frames.filter((frame) => frame.type === "command_receipt").at(-1) as Record<string, any>;
	expect(receipt.state).toBe("applied");
	expect(receipt.evidence).toBe("questions_answered");

	// The point of the whole exercise: what the model is handed. Without the PostToolUse
	// substitution this is "The user did not answer the questions." — the tool runs headlessly,
	// finds no interface to ask through, and reports that nothing was chosen.
	await eventually(() =>
		frames.some(
			(frame) =>
				frame.type === "upsert_entry" &&
				(frame as any).entry?.body?.tool?.result_preview !== undefined,
		),
	);
	const result = frames.find(
		(frame) =>
			frame.type === "upsert_entry" && (frame as any).entry?.body?.tool?.result_preview !== undefined,
	) as Record<string, any>;
	const output = JSON.parse(result.entry.body.tool.result_preview);
	expect(output.answers).toEqual({
		"Which transport should it use?": "Relay only",
		// Multi-select answers are comma-separated, and the free-text "Other" stands alongside
		// the chosen options rather than replacing them.
		"Which platforms should it cover?": "macOS, and FreeBSD",
	});
	// The questions are echoed back with multiSelect resolved, which is the documented shape.
	expect(output.questions).toHaveLength(2);
	expect(output.questions[1].multiSelect).toBe(true);
});

/// A catalogue is only useful if it describes what this account can really run, so it comes from
/// the SDK rather than from anything compiled into Ciao — and it has to survive a vendor list
/// that is longer, or wordier, than the frame budget allows.
test("the catalogue published after registration is the vendor's, bounded to what a frame can carry", async () => {
	const { frames } = await startWorker(
		[],
		undefined,
		undefined,
		[
			{
				value: "claude-opus-5[1m]",
				resolvedModel: "claude-opus-5",
				displayName: "Opus 5 (1M)",
				description: "Prose the picker has no room for and should never carry.",
				supportsEffort: true,
				supportedEffortLevels: ["low", "medium", "high", "xhigh", "max"],
			},
			{
				value: "claude-sonnet-5",
				displayName: "Sonnet 5",
				description: "More prose.",
				supportsEffort: false,
			},
			// Over the id bound: dropped whole, because half an identifier names nothing.
			{ value: `claude-${"x".repeat(70)}`, displayName: "Too long an id" },
			// Over the display bound: dropped whole rather than clipped, because a clipped name
			// would be offered as a choice nobody can read.
			{ value: "claude-wordy", displayName: "N".repeat(49) },
			// A level the pin does not define is not carried through as if it were real.
			{ value: "claude-odd", displayName: "Odd", supportsEffort: true, supportedEffortLevels: ["high", "ludicrous"] },
		],
	);
	await eventually(() => frames.some((frame) => frame.type === "model_catalogue"));
	const published = frames.find((frame) => frame.type === "model_catalogue") as Record<string, any>;

	expect(published.models.map((row: any) => row.value)).toEqual([
		"claude-opus-5[1m]",
		"claude-sonnet-5",
		"claude-odd",
	]);
	// Vendor prose never crosses the boundary.
	expect(JSON.stringify(published)).not.toContain("Prose the picker");
	expect(JSON.stringify(published)).not.toContain("description");
	expect(published.models[0]).toEqual({
		value: "claude-opus-5[1m]",
		display_name: "Opus 5 (1M)",
		supports_effort: true,
		supported_effort_levels: ["low", "medium", "high", "xhigh", "max"],
	});
	expect(published.models[1].supports_effort).toBe(false);
	expect(published.models[1].supported_effort_levels).toEqual([]);
	expect(published.models[2].supported_effort_levels).toEqual(["high"]);
	// The catalogue says what can be run; it never claims to know what *is* running.
	expect(frames.some((frame) => frame.type === "model")).toBe(false);
});

/// The model that answered is the only model worth reporting, and it is read off the message the
/// model produced rather than inferred from what was asked for.
test("the answering model is reported from the SDK's own message, once, and never guessed", async () => {
	const { frames } = await startWorker(
		[
			{
				type: "assistant",
				uuid: "a1",
				message: { id: "m1", model: "claude-opus-5[1m]", content: [{ type: "text", text: "One." }] },
			},
			{
				type: "assistant",
				uuid: "a2",
				message: { id: "m2", model: "claude-opus-5[1m]", content: [{ type: "text", text: "Two." }] },
			},
			{
				type: "assistant",
				uuid: "a3",
				message: { id: "m3", model: "claude-sonnet-5", content: [{ type: "text", text: "Three." }] },
			},
		],
		undefined,
		undefined,
		[{ value: "claude-opus-5[1m]", displayName: "Opus 5" }],
	);
	await eventually(() => frames.filter((frame) => frame.type === "model").length === 2);
	expect(frames.filter((frame) => frame.type === "model").map((frame: any) => frame.model)).toEqual([
		"claude-opus-5[1m]",
		"claude-sonnet-5",
	]);
});

/// Never optimistic: the receipt follows the SDK accepting the change, and the state frame
/// follows the receipt. The phone moves on the report, not on the request.
test("a model change is applied through the SDK and only then reported", async () => {
	const { frames, send, journal } = await startWorker(
		[],
		undefined,
		undefined,
		[
			{ value: "claude-opus-5[1m]", displayName: "Opus 5" },
			{ value: "claude-sonnet-5", displayName: "Sonnet 5" },
		],
		undefined,
		true,
	);
	await eventually(() => frames.some((frame) => frame.type === "model_catalogue"));

	send({ v: 1, type: "command", command_id: "command-model", kind: "set_model", model: "claude-sonnet-5" });
	await eventually(() => frames.some((frame) => frame.type === "model"));

	const receipt = frames.find((frame) => frame.type === "command_receipt") as Record<string, any>;
	expect(receipt.state).toBe("applied");
	expect(receipt.evidence).toBe("model_set");
	expect(journal().setModel).toEqual(["claude-sonnet-5"]);

	// Order is the contract: the SDK accepted it, then the receipt, then the statement of what
	// the session now is.
	const receiptIndex = frames.findIndex((frame) => frame.type === "command_receipt");
	const stateIndex = frames.findIndex((frame) => frame.type === "model");
	expect(stateIndex).toBeGreaterThan(receiptIndex);
	expect((frames[stateIndex] as any).model).toBe("claude-sonnet-5");
});

/// The catalogue is the authority on which models exist, so a model outside it is refused here
/// rather than discovered by the vendor.
test("a model outside the published catalogue is refused categorically", async () => {
	const { frames, send, journal } = await startWorker(
		[],
		undefined,
		undefined,
		[{ value: "claude-opus-5[1m]", displayName: "Opus 5" }],
		undefined,
		true,
	);
	await eventually(() => frames.some((frame) => frame.type === "model_catalogue"));

	send({ v: 1, type: "command", command_id: "command-bad", kind: "set_model", model: "gpt-9" });
	await eventually(() => frames.some((frame) => frame.type === "command_receipt"));

	const receipt = frames.find((frame) => frame.type === "command_receipt") as Record<string, any>;
	expect(receipt.state).toBe("rejected");
	expect(receipt.reason_code).toBe("unsupported_model");
	// Refused before the SDK was touched at all.
	expect(journal().setModel).toEqual([]);
	expect(frames.some((frame) => frame.type === "model")).toBe(false);
});

/// The vendor names one model two ways and Ciao has to pick one. A catalogue row's `value` is what
/// `setModel` accepts and what the picker tags its rows with (`sonnet`, `default`, `opus[1m]`);
/// every model the SDK *reports* — on `system/init`, on every assistant message — is the resolved
/// wire id it stands for (`claude-sonnet-5`). Reporting the raw form put an id on the wire that
/// matched no row, so the phone's bar fell back to the wire id or to nothing. The catalogue's form
/// is the one that goes out.
test("a reported model is normalised to the catalogue id the picker tags rows with", async () => {
	const { frames } = await startWorker(
		[
			{
				type: "assistant",
				uuid: "a1",
				message: { id: "m1", model: "claude-sonnet-5", content: [{ type: "text", text: "One." }] },
			},
			// The same model answering again is still one frame: the dedupe has to survive the
			// rewrite, or a steady conversation reports a model change per message.
			{
				type: "assistant",
				uuid: "a2",
				message: { id: "m2", model: "claude-sonnet-5", content: [{ type: "text", text: "Two." }] },
			},
			// A wire id no row resolves to is reported as it came. Truth over prettiness: the phone
			// shows what is answering even when Ciao has no nicer name for it, and a model absent
			// from the catalogue is exactly the case worth seeing.
			{
				type: "assistant",
				uuid: "a3",
				message: { id: "m3", model: "claude-opus-5", content: [{ type: "text", text: "Three." }] },
			},
		],
		undefined,
		undefined,
		[
			{ value: "sonnet", resolvedModel: "claude-sonnet-5", displayName: "Sonnet" },
			// The vendor's own explicit-id row does not name itself either: `[1m]` is on the id you
			// ask for and off the id that answers.
			{ value: "claude-fable-5[1m]", resolvedModel: "claude-fable-5", displayName: "Fable" },
		],
	);
	await eventually(() => frames.filter((frame) => frame.type === "model").length === 2);

	expect(frames.filter((frame) => frame.type === "model").map((frame: any) => frame.model)).toEqual([
		"sonnet",
		"claude-opus-5",
	]);
});

/// The SDK is lazy about a session id but not about a model: `system/init` carries the model the
/// turn is starting on, and it arrives before the model has said anything. That is the earliest
/// moment this worker can tell the truth, so it tells it there rather than waiting for an answer.
test("the model is reported from system/init, before anything has answered", async () => {
	const { frames } = await startWorker(
		[{ type: "system", subtype: "init", session_id: "vendor-session-1", model: "claude-sonnet-5" }],
		undefined,
		undefined,
		[{ value: "sonnet", resolvedModel: "claude-sonnet-5", displayName: "Sonnet" }],
		undefined,
		true,
	);
	await eventually(() => frames.some((frame) => frame.type === "model"));

	// Reported in the catalogue's form, from a session that has produced no assistant message at
	// all — the state the bar was empty in.
	expect((frames.find((frame) => frame.type === "model") as any).model).toBe("sonnet");
	expect(frames.some((frame) => frame.type === "entry")).toBe(false);
	// The session identity still rides the same message.
	expect(frames.some((frame) => frame.type === "vendor_session")).toBe(true);
});

/// A resumed session was launched onto a model the host chose. That is not a guess about the
/// vendor's default — it is what this worker put in `Options.model` — so it is reportable at
/// registration, before the SDK has been asked anything.
///
/// It also pins the tie. Two rows can resolve to one wire id (the vendor ships `default` and
/// `opus[1m]` both standing for `claude-opus-5[1m]`), and a pick already standing wins it:
/// otherwise choosing "Opus (1M context)" would redraw itself as "Default (recommended)" the
/// instant the model answered.
test("a model the worker was launched on is reported at once, and survives the answer", async () => {
	const { frames } = await startWorker(
		[
			{
				type: "assistant",
				uuid: "a1",
				message: { id: "m1", model: "claude-opus-5[1m]", content: [{ type: "text", text: "Hi." }] },
			},
		],
		undefined,
		undefined,
		[
			{ value: "default", resolvedModel: "claude-opus-5[1m]", displayName: "Default (recommended)" },
			{ value: "opus[1m]", resolvedModel: "claude-opus-5[1m]", displayName: "Opus (1M context)" },
		],
		{ CIAO_MANAGED_MODEL: "opus[1m]" },
		true,
	);
	await eventually(() => frames.some((frame) => frame.type === "model"));
	await eventually(() => frames.some((frame) => frame.type === "model_catalogue"));

	// One frame, before the catalogue and never restated: the answer belonged to the row already
	// held, so there was nothing new to say.
	expect(frames.filter((frame) => frame.type === "model").map((frame: any) => frame.model)).toEqual([
		"opus[1m]",
	]);
});

/// The vendor drops a context-window suffix when it says which model answered, and this is not a
/// guess: against the live SDK a session reports `claude-opus-5[1m]` on `system/init` and then
/// `claude-opus-5` on the message it produces, while the only rows covering it (`default` and
/// `opus[1m]`) both resolve to the bracketed form. Left alone the bar names the model correctly
/// and then replaces that name with a wire id the moment the first answer lands — the reported
/// defect, arriving late.
///
/// So a suffix is tolerated, but only after every exact reading has failed: an account whose
/// catalogue really does carry both windows matches one exactly and never reaches this.
test("a model that answers without its context-window suffix keeps the row that covers it", async () => {
	const { frames } = await startWorker(
		[
			{ type: "system", subtype: "init", session_id: "vendor-session-1", model: "claude-opus-5[1m]" },
			{
				type: "assistant",
				uuid: "a1",
				message: { id: "m1", model: "claude-opus-5", content: [{ type: "text", text: "Hi." }] },
			},
		],
		undefined,
		undefined,
		[
			{ value: "default", resolvedModel: "claude-opus-5[1m]", displayName: "Default (recommended)" },
			{ value: "opus[1m]", resolvedModel: "claude-opus-5[1m]", displayName: "Opus (1M context)" },
		],
		undefined,
		true,
	);
	await eventually(() => frames.some((frame) => frame.type === "model"));
	// Nothing else is coming; give the answer a chance to wrongly restate the model.
	await Bun.sleep(200);

	expect(frames.filter((frame) => frame.type === "model").map((frame: any) => frame.model)).toEqual([
		"default",
	]);
});

/// The tolerance above is a last resort, not a rule about brackets. An account that publishes both
/// windows as their own rows has an exact answer for each, and the narrow window must not be read
/// as the wide one.
test("a suffix is only ever dropped when no row reads the id exactly", async () => {
	const { frames } = await startWorker(
		[
			{
				type: "assistant",
				uuid: "a1",
				message: { id: "m1", model: "claude-opus-5", content: [{ type: "text", text: "Hi." }] },
			},
		],
		undefined,
		undefined,
		[
			{ value: "opus[1m]", resolvedModel: "claude-opus-5[1m]", displayName: "Opus (1M context)" },
			{ value: "opus", resolvedModel: "claude-opus-5", displayName: "Opus" },
		],
	);
	await eventually(() => frames.some((frame) => frame.type === "model"));

	expect((frames.find((frame) => frame.type === "model") as any).model).toBe("opus");
});

/// With nothing picked, the tie goes to the row the vendor listed first — `default` covers
/// `claude-opus-5[1m]` as truly as `opus[1m]` does, and it is the honest one: nobody chose Opus,
/// the session is simply running the vendor's default and should say so.
test("with nothing picked, a wire id two rows claim is read as the vendor's first row", async () => {
	const { frames } = await startWorker(
		[
			{
				type: "assistant",
				uuid: "a1",
				message: { id: "m1", model: "claude-opus-5[1m]", content: [{ type: "text", text: "Hi." }] },
			},
		],
		undefined,
		undefined,
		[
			{ value: "default", resolvedModel: "claude-opus-5[1m]", displayName: "Default (recommended)" },
			{ value: "opus[1m]", resolvedModel: "claude-opus-5[1m]", displayName: "Opus (1M context)" },
		],
	);
	await eventually(() => frames.some((frame) => frame.type === "model"));

	expect((frames.find((frame) => frame.type === "model") as any).model).toBe("default");
});

/// Effort is gated on the active model's own levels, so the gate has to find the row. It looks the
/// active model up by catalogue id, which only works because everything reported is normalised to
/// one — a session running on a resolved wire id used to reach the gate as an id no row carried.
test("effort is gated against the right row when the model arrived in the SDK's own form", async () => {
	const { frames, send, journal } = await startWorker(
		[
			{
				type: "assistant",
				uuid: "a1",
				message: { id: "m1", model: "claude-sonnet-5", content: [{ type: "text", text: "Hi." }] },
			},
		],
		undefined,
		undefined,
		[
			{
				value: "sonnet",
				resolvedModel: "claude-sonnet-5",
				displayName: "Sonnet",
				supportsEffort: true,
				supportedEffortLevels: ["low", "high"],
			},
		],
		undefined,
		true,
	);
	await eventually(() => frames.some((frame) => frame.type === "model"));

	send({ v: 1, type: "command", command_id: "command-effort", kind: "set_effort", effort: "high" });
	await eventually(() => frames.some((frame) => frame.type === "effort"));

	expect(journal().flagSettings).toEqual([{ effortLevel: "high" }]);
	// And a level that row does not offer is still refused, so the gate is reading the row rather
	// than waving everything through.
	send({ v: 1, type: "command", command_id: "command-effort-2", kind: "set_effort", effort: "max" });
	await eventually(() => frames.filter((frame) => frame.type === "command_receipt").length === 2);
	const refusal = frames.filter((frame) => frame.type === "command_receipt")[1] as Record<string, any>;
	expect(refusal.state).toBe("rejected");
	expect(refusal.reason_code).toBe("unsupported_effort");
});

/// There is no setEffort. Effort rides the flag-settings layer, and because successive calls
/// shallow-merge top-level keys, exactly one scalar key may be sent.
test("effort is applied through flag settings as a single scalar key, and reported after", async () => {
	const { frames, send, journal } = await startWorker(
		[
			{
				type: "assistant",
				uuid: "a1",
				message: { id: "m1", model: "claude-opus-5[1m]", content: [{ type: "text", text: "Hi." }] },
			},
		],
		undefined,
		undefined,
		[
			{
				value: "claude-opus-5[1m]",
				displayName: "Opus 5",
				supportsEffort: true,
				supportedEffortLevels: ["low", "high", "max"],
			},
		],
		undefined,
		true,
	);
	// Effort is checked against the *active* model, so the session has to know one first.
	await eventually(() => frames.some((frame) => frame.type === "model"));

	send({ v: 1, type: "command", command_id: "command-effort", kind: "set_effort", effort: "max" });
	await eventually(() => frames.some((frame) => frame.type === "effort"));

	expect(journal().flagSettings).toEqual([{ effortLevel: "max" }]);
	const receipt = frames.find((frame) => frame.type === "command_receipt") as Record<string, any>;
	expect(receipt.state).toBe("applied");
	expect(receipt.evidence).toBe("effort_set");
	expect((frames.find((frame) => frame.type === "effort") as any).effort).toBe("max");
});

/// The SDK silently downgrades an effort the chosen model cannot do. A silent downgrade would
/// leave the phone showing a level the session is not running at, so it is refused instead.
test("an effort the active model does not offer is refused rather than silently downgraded", async () => {
	const { frames, send, journal } = await startWorker(
		[
			{
				type: "assistant",
				uuid: "a1",
				message: { id: "m1", model: "claude-sonnet-5", content: [{ type: "text", text: "Hi." }] },
			},
		],
		undefined,
		undefined,
		[
			{
				value: "claude-sonnet-5",
				displayName: "Sonnet 5",
				supportsEffort: true,
				supportedEffortLevels: ["low", "medium"],
			},
		],
		undefined,
		true,
	);
	await eventually(() => frames.some((frame) => frame.type === "model"));

	send({ v: 1, type: "command", command_id: "command-effort-bad", kind: "set_effort", effort: "max" });
	await eventually(() => frames.some((frame) => frame.type === "command_receipt"));

	const receipt = frames.find((frame) => frame.type === "command_receipt") as Record<string, any>;
	expect(receipt.state).toBe("rejected");
	expect(receipt.reason_code).toBe("unsupported_effort");
	expect(journal().flagSettings).toEqual([]);
	expect(frames.some((frame) => frame.type === "effort")).toBe(false);
});

/// A resumed conversation continues on the model it was already being answered by. The host
/// reads that from Claude's own transcript and passes it; this is the half that has to arrive.
test("a model handed in at launch reaches the SDK's own options", async () => {
	const { frames, journal } = await startWorker(
		[],
		undefined,
		undefined,
		[{ value: "claude-opus-5[1m]", displayName: "Opus 5" }],
		{ CIAO_MANAGED_MODEL: "claude-opus-5[1m]" },
	);
	await eventually(() => frames.some((frame) => frame.type === "model_catalogue"));
	expect(journal().options.model).toBe("claude-opus-5[1m]");
});

/// A fresh session has nothing to inherit and must start wherever the vendor's default is,
/// never on a model this worker picked.
test("a session with no inherited model asks the SDK for none", async () => {
	const { frames, journal } = await startWorker(
		[],
		undefined,
		undefined,
		[{ value: "claude-opus-5[1m]", displayName: "Opus 5" }],
	);
	await eventually(() => frames.some((frame) => frame.type === "model_catalogue"));
	expect(journal().options.model).toBe(null);
});

/// A pin that cannot publish a catalogue costs the phone its picker — a missing control — and
/// must not cost it the session.
test("a pin without the catalogue surface keeps working and offers nothing to pick", async () => {
	const { frames, send } = await startWorker(
		[
			{
				type: "assistant",
				uuid: "a1",
				message: { id: "m1", model: "claude-opus-5[1m]", content: [{ type: "text", text: "Still working." }] },
			},
		],
		undefined,
		undefined,
		undefined,
		undefined,
		true,
	);
	await eventually(() =>
		frames.some((frame) => frame.type === "upsert_entry" && (frame as any).entry.kind === "assistant_message"),
	);
	expect(frames.some((frame) => frame.type === "model_catalogue")).toBe(false);

	// And a model command with no catalogue to check against is refused, not guessed.
	send({ v: 1, type: "command", command_id: "command-nocat", kind: "set_model", model: "claude-sonnet-5" });
	await eventually(() => frames.some((frame) => frame.type === "command_receipt"));
	const receipt = frames.find((frame) => frame.type === "command_receipt") as Record<string, any>;
	expect(receipt.state).toBe("rejected");
	expect(receipt.reason_code).toBe("model_catalogue_unavailable");
});

/// The CLI answers slash commands and notices with a synthetic assistant message whose model is
/// "<synthetic>" — an artifact, not a model. Reporting it killed the session: the daemon refuses
/// the value (`valid_model_id`) and one refused frame ends the whole bridge, which is how a
/// phone-sent `/config` turned a live takeover into an invisible zombie (2026-08-09). The text
/// itself is the graceful fallback and must still arrive.
test("a synthetic assistant message is shown, and its non-model is never reported", async () => {
	const { frames } = await startWorker(
		[
			{
				type: "assistant",
				uuid: "a1",
				message: {
					id: "m1",
					model: "<synthetic>",
					content: [{ type: "text", text: "Usage: /config key=value" }],
				},
			},
			{
				type: "assistant",
				uuid: "a2",
				message: { id: "m2", model: "claude-opus-5", content: [{ type: "text", text: "Real." }] },
			},
		],
		undefined,
		undefined,
		[{ value: "claude-opus-5", displayName: "Opus 5" }],
	);
	// The second message being mapped proves the first one's model was already decided on.
	await eventually(() =>
		frames.some((frame) => frame.type === "upsert_entry" && JSON.stringify(frame).includes("Real.")),
	);
	// The command's answer reaches the timeline — refusing the model must not eat the text.
	expect(
		frames.some(
			(frame) => frame.type === "upsert_entry" && JSON.stringify(frame).includes("Usage: /config"),
		),
	).toBe(true);
	expect(frames.filter((frame) => frame.type === "model").map((frame: any) => frame.model)).toEqual([
		"claude-opus-5",
	]);
	expect(JSON.stringify(frames)).not.toContain("<synthetic>");
});

/// A dropped daemon connection arrives as 'end' + 'close', never 'error', and writes to a
/// destroyed socket return false without ever erroring — so a worker that only watched 'error'
/// outlived its bridge indefinitely, invisible to every list and unable to re-register (spawn
/// tokens are one-time). Exiting nonzero is what turns that state into a truthful stored
/// (worker_crash) row the phone can resume.
/// A finished message is a display body, not a wire delta: the host renders up to its 48 KiB
/// timeline bound (MAX_TIMELINE_TEXT_BYTES) and the attached adapter already delivers that
/// much, but the managed worker used to cut the same reply at the 16 KiB delta bound because
/// that constant was textBody's default. Between the two sizes nothing may be lost.
test("a finished message between the delta and timeline bounds arrives whole", async () => {
	const midText = "m".repeat(20 * 1024);
	const overText = "o".repeat(50 * 1024);
	const { frames } = await startWorker([
		{ type: "user", isReplay: true, uuid: "u1", message: { content: "write a long reply" } },
		{
			type: "assistant",
			uuid: "a1",
			message: { id: "m1", content: [{ type: "text", text: midText }] },
		},
		{
			type: "assistant",
			uuid: "a2",
			message: { id: "m2", content: [{ type: "text", text: overText }] },
		},
		{ type: "result", subtype: "success" },
	]);
	await eventually(() =>
		frames.some((frame) => frame.type === "turn" && frame.state === "completed"),
	);

	const finished = frames.filter(
		(frame) => frame.type === "upsert_entry" && (frame as any).entry.kind === "assistant_message",
	) as any[];
	expect(finished.map((frame) => frame.entry.source_id)).toEqual([
		"assistant-m1",
		"assistant-m2",
	]);
	expect(finished[0].entry.body.text).toBe(midText);
	expect(finished[0].entry.truncation).toEqual({ truncated: false });
	// Past the host's own render bound the worker still truncates, and says so.
	expect(finished[1].entry.body.text.length).toBe(48 * 1024);
	expect(finished[1].entry.truncation).toEqual({
		truncated: true,
		reason_code: "content_bound",
	});
});

test("a worker whose bridge drops exits instead of running on invisibly", async () => {
	const { child, frames, dropPeer } = await startWorker(
		[],
		undefined,
		undefined,
		undefined,
		undefined,
		true,
	);
	await eventually(() => frames.some((frame) => frame.type === "register"));
	dropPeer();
	await eventually(() => child.exitCode !== null);
	expect(child.exitCode).toBe(1);
});
