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
const CONFIGURATION = JSON.parse(fs.readFileSync(
	path.join(import.meta.dir, "../../../protocol/fixtures/phase5/destination-configuration-v1.json"), "utf8",
));
const SESSION_ID = "0123456789abcdef0123456789abcdef";
// The worker's exit codes, from the fixture the daemon's reaper reads too.
const EXITS: Array<{ code: number; cause: string; vendor_prefix?: string }> = JSON.parse(fs.readFileSync(
	path.join(import.meta.dir, "../../../protocol/fixtures/phase5/managed-worker-exit-v1.json"), "utf8",
)).exits;
const exitFor = (cause: string) => EXITS.find((exit) => exit.cause === cause)!;
// A vendor that ended the session before the worker handed it a prompt. A fake whose script runs
// out before any prompt is exactly that vendor, so a test that waits for the worker to finish
// such a script sees this code rather than 0.
const VENDOR_ENDED_UNPROMPTED_EXIT = exitFor("vendor_ended_unprompted").code;

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

type PermissionFixture = {
	tool: unknown;
	input: unknown;
	suggestions?: unknown;
	toolUseID?: string;
	preabort?: boolean;
	abortDuringAttach?: boolean;
	abortAfterAnswer?: boolean;
	inputKind?: "cycle" | "bigint" | "getter" | "toJSON" | "deep" | "oversized" | "proxy" | "nestedProxy" | "arrayProxy" | "revoked" | "nestedRevoked";
};
type PermissionScenario = PermissionFixture | { requests: PermissionFixture[]; concurrent: boolean };

function plantFakeSdk(
	root: string,
	script: unknown[],
	permission?: PermissionScenario,
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
const journal = { options: null, setModel: [], flagSettings: [], promptContexts: [], permissionRequests: [], permissionDecisions: [], proxyTraps: [] };
const permissionControllers = new Set();
function record() {
	// Publish atomically so the parent never reads the truncation window of a rewrite.
	try {
		fs.writeFileSync(JOURNAL + ".tmp", JSON.stringify(journal));
		fs.renameSync(JOURNAL + ".tmp", JOURNAL);
	} catch {}
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
		settingSources: config.options.settingSources ?? null,
		settings: config.options.settings ?? null,
		systemPrompt: config.options.systemPrompt ?? null,
		extraArgs: config.options.extraArgs,
		hooks: Object.keys(config.options.hooks ?? {}),
		launchPolicyLeaked: Object.hasOwn(config.options.env, "CIAO_AGENT_CONFIGURATION"),
	};
	record();
	// Each prompt the worker streams in, read the way the real SDK reads it: UserPromptSubmit
	// hooks run as the prompt is submitted, and what they add is what the model is handed.
	(async () => {
		for await (const message of config.prompt) {
			const content = message && message.message && message.message.content;
			const text = Array.isArray(content)
				? content.map((part) => (part && part.text) || "").join("")
				: String(content ?? "");
			let context = null;
			for (const matcher of (config.options.hooks && config.options.hooks.UserPromptSubmit) || []) {
				for (const hook of matcher.hooks) {
					const result = await hook({ hook_event_name: "UserPromptSubmit", prompt: text });
					const added = result && result.hookSpecificOutput && result.hookSpecificOutput.additionalContext;
					if (added !== undefined) context = added;
				}
			}
			journal.promptContexts.push({ prompt: text, context });
			record();
		}
	})();
	return {
		async *[Symbol.asyncIterator]() {
			// Let registration settle first, so the frame order under test is the real one.
			await new Promise((resolve) => setTimeout(resolve, 150));
			if (PERMISSION) {
				const invoke = async (request) => {
					const toolUseID = request.toolUseID ?? TOOL_USE_ID;
					const controller = new AbortController();
					permissionControllers.add(controller);
					if (request.preabort) controller.abort();
					const listeners = new Set();
					const add = controller.signal.addEventListener.bind(controller.signal);
					const remove = controller.signal.removeEventListener.bind(controller.signal);
					controller.signal.addEventListener = (...args) => {
						listeners.add(args[1]);
						add(...args);
						if (request.abortDuringAttach) controller.abort();
					};
					controller.signal.removeEventListener = (...args) => { listeners.delete(args[1]); remove(...args); };
					let input = request.input;
					if (request.inputKind === "cycle") { input = {}; input.self = input; }
					if (request.inputKind === "bigint") input = { value: 1n };
					if (request.inputKind === "getter") input = { get value() { throw Error("synthetic getter"); } };
					if (request.inputKind === "toJSON") input = { toJSON() { return {}; } };
					if (request.inputKind === "deep") { input = {}; for (let i = 0; i < 1000; i++) input = { nested: input }; }
					if (request.inputKind === "oversized") input = { value: "x".repeat(16 * 1024) };
					if (["proxy", "nestedProxy", "arrayProxy", "revoked", "nestedRevoked"].includes(request.inputKind)) {
						const handler = Object.fromEntries(["get", "getPrototypeOf", "ownKeys", "getOwnPropertyDescriptor"].map(name => [name, (...args) => {
							journal.proxyTraps.push(name); record();
							return Reflect[name](...args);
						}]));
						const pair = Proxy.revocable(request.inputKind === "arrayProxy" ? [] : { command: "synthetic" }, handler);
						if (["revoked", "nestedRevoked"].includes(request.inputKind)) pair.revoke();
						input = request.inputKind === "nestedProxy" || request.inputKind === "nestedRevoked" || request.inputKind === "arrayProxy"
							? { nested: [pair.proxy] } : pair.proxy;
					}
					journal.permissionRequests.push({ tool: request.tool, input: request.input, toolUseID });
					record();
					const decision = await config.options.canUseTool(request.tool, input, {
						signal: controller.signal,
						...(Object.hasOwn(request, "suggestions") ? { suggestions: request.suggestions } : {}),
						toolUseID,
						requestId: "request-" + toolUseID,
					});
					permissionControllers.delete(controller);
					if (request.abortAfterAnswer) {
						controller.abort();
						controller.signal.dispatchEvent(new Event("abort"));
					}
					journal.permissionListeners ??= [];
					journal.permissionListeners.push(listeners.size);
					journal.permissionDecisions.push({ toolUseID, decision });
					record();
					let output = "The user did not answer the questions.";
					if (decision && decision.behavior === "allow") {
						for (const matcher of (config.options.hooks && config.options.hooks.PostToolUse) || []) {
							for (const hook of matcher.hooks) {
								const result = await hook({
									hook_event_name: "PostToolUse",
									tool_name: request.tool,
									tool_input: request.input,
									tool_response: output,
									tool_use_id: toolUseID,
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
					return {
						type: "user",
						message: {
							content: [
								{
									type: "tool_result",
									tool_use_id: toolUseID,
									content: [
										{ type: "text", text: typeof output === "string" ? output : JSON.stringify(output) },
									],
								},
							],
						},
					};
				};
				const requests = PERMISSION.requests ?? [PERMISSION];
				if (PERMISSION.concurrent) {
					for (const result of await Promise.all(requests.map(invoke))) yield result;
				} else {
					for (const request of requests) yield await invoke(request);
				}
			}
			for (const message of SCRIPT) {
				// The real SDK throws once the CLI it spawned exits nonzero, after the result.
				if (message.fake_throw) throw new Error(message.fake_throw);
				// Holds the stream until the worker has handed the SDK a prompt, so a test can
				// end the session after one rather than racing the command it sent.
				if (message.fake_await_prompt) {
					while (journal.promptContexts.length === 0) await new Promise((resolve) => setTimeout(resolve, 10));
					continue;
				}
                if (message.hook_event_name) {
                    for (const matcher of config.options.hooks[message.hook_event_name] ?? []) {
                        for (const hook of matcher.hooks) await hook(message);
                    }
                    continue;
                }
				yield message;
				await new Promise((resolve) => setTimeout(resolve, 10));
			}
			// A real session sits waiting for the next prompt rather than ending the moment it
			// stops talking. Command tests need that window; the harness kills the child after.
			if (HOLD) await new Promise(() => {});
		},
		async interrupt() {
			for (const controller of permissionControllers) {
				controller.abort();
				controller.signal.dispatchEvent(new Event("abort"));
			}
		},
		async setPermissionMode() { return { mode: "plan" }; },
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
	journal: () => {
		options: any;
		setModel: unknown[];
		flagSettings: unknown[];
		promptContexts: Array<{ prompt: string; context: string | null }>;
		permissionRequests: Array<{ tool: string; input: unknown; toolUseID: string }>;
		permissionDecisions: Array<{ toolUseID: string; decision: Record<string, unknown> }>;
		permissionListeners: number[];
		proxyTraps: string[];
	};
};

/// One worker, run the way the daemon runs it, with the socket left open so a test can answer
/// what the worker raises.
async function startWorker(
	script: unknown[],
	permission?: PermissionScenario,
	history?: HistoryFixture,
	models?: unknown[],
	extraEnv?: Record<string, string>,
	hold?: boolean,
	bridge: { eofOnRegister?: boolean; runtime?: string; grant?: number } = {},
): Promise<Harness> {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "ciao-managed-worker-"));
	const socketPath = path.join(root, "agent.sock");
	const frames: Record<string, unknown>[] = [];
	let peer: net.Socket | undefined;

	const server = net.createServer({ allowHalfOpen: Boolean(bridge.eofOnRegister) }, (socket) => {
		peer = socket;
		socket.on(
			"data",
			decodeFrames((frame) => {
				frames.push(frame);
				if (frame.type === "register") {
					const registered = encodeFrame({
						v: 1,
						type: "registered",
						session_id: SESSION_ID,
						process_generation: 1,
						snapshot_epoch: 1,
						// A current daemon grants its bridge bound; without it this plays one from
						// before the grant.
						...(bridge.grant ? { frame_bytes: bridge.grant } : {}),
					});
					if (bridge.eofOnRegister) {
						// Send the acknowledgement and EOF together, but never drain the snapshot.
						// This keeps the worker's writes backpressured after its command side ends.
						socket.pause();
						socket.end(registered);
					} else {
						socket.write(registered);
					}
				}
			}),
		);
	});
	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(socketPath, resolve);
	});

	plantFakeSdk(root, script, permission, history, models, hold);

	const child = Bun.spawn([bridge.runtime ?? process.execPath, WORKER], {
		env: {
			...process.env,
			CIAO_MANAGED_SOCKET: socketPath,
			CIAO_MANAGED_SDK_PREFIX: root,
			CIAO_MANAGED_SESSION_ID: SESSION_ID,
			CIAO_MANAGED_SPAWN_TOKEN: "fedcba9876543210fedcba9876543210",
			CIAO_MANAGED_WORKSPACE_LABEL: "workspace",
			CIAO_MANAGED_CLI_VERSION: "2.1.332",
			CIAO_MANAGED_SDK_VERSION: "0.3.332",
			[CONFIGURATION.environment_key]: CONFIGURATION.adapters["claude-managed"],
			// Tests never consult the developer's settings or browser preference.
			CLAUDE_CONFIG_DIR: path.join(root, "config"),
			CLAUDE_CODE_ENABLE_CFC: undefined,
			...(history ? { CIAO_MANAGED_RESUME_SESSION_ID: history.sessionID } : {}),
			...(extraEnv ?? {}),
		},
		stdout: "pipe",
		stderr: "pipe",
	});
	resources.push(async () => {
		child.kill();
		peer?.destroy();
		await child.exited;
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
				return { options: null, setModel: [], flagSettings: [], promptContexts: [], permissionRequests: [], permissionDecisions: [], permissionListeners: [] };
			}
		},
	};
}

test("destination configuration loads all settings without replacing fresh-session defaults", async () => {
	const { journal, frames } = await startWorker([], undefined, undefined, undefined, undefined, true);
	await eventually(() => journal().options !== null);
	expect(journal().options.settingSources).toEqual(CONFIGURATION.claude_setting_sources);
	expect(journal().options.systemPrompt).toEqual(CONFIGURATION.claude_system_prompt);
	expect(journal().options.permissionMode).toBeNull();
	expect(journal().options.model).toBeNull();
	expect(journal().options.settings).toBeNull();
	expect(journal().options.launchPolicyLeaked).toBe(false);
	expect(journal().options.hooks.sort()).toEqual(["Notification", "PostToolUse", "PostToolUseFailure", "PreToolUse", "SubagentStart", "SubagentStop", "UserPromptSubmit"]);
	// Until the vendor reports its resolved mode, a default would be an invented fact.
	expect(frames.filter((frame) => frame.type === "permission_mode")).toEqual([]);
});

test("Code Mode opt-in is an SDK flag setting", async () => {
	const { journal } = await startWorker([], undefined, undefined, undefined,
		{ CIAO_MANAGED_CODE_MODE: "1" }, true);
	await eventually(() => journal().options !== null);
	expect(journal().options.settings).toEqual({ env: { CLAUDE_CODE_EXPERIMENTAL_CODE_MODE: "1" } });
});

test("a mode change reports the effective SDK mode", async () => {
	const { frames, send } = await startWorker([], undefined, undefined, undefined, undefined, true);
	await eventually(() => frames.some(frame => frame.type === "snapshot_end"));
	send({ v: 1, type: "command", kind: "set_permission_mode", command_id: "mode-differs", mode: "acceptEdits" });
	await eventually(() => frames.some(frame => frame.type === "permission_mode" && frame.mode === "plan"));
	expect(frames.find(frame => frame.command_id === "mode-differs")).toMatchObject({
		state: "rejected", reason_code: "permission_mode_failed",
	});
});

test("destination configuration preserves a resumed mode and reports the vendor's resolved mode", async () => {
	const { journal, frames } = await startWorker(
		[{ type: "system", subtype: "init", permissionMode: "plan" }],
		undefined, undefined, undefined, { CIAO_MANAGED_PERMISSION_MODE: "acceptEdits" },
	);
	await eventually(() => frames.some((frame: any) => frame.type === "permission_mode" && frame.mode === "plan"));
	expect(journal().options.permissionMode).toBe("acceptEdits");
});

test("future_shaped_input_permission_mode_is_tallied_without_inventing_session_state", async () => {
	const { frames, child } = await startWorker([
		{ type: "system", subtype: "init", permissionMode: "future-mode" },
	]);
	expect(await child.exited).toBe(VENDOR_ENDED_UNPROMPTED_EXIT);
	expect(frames.filter((frame) => frame.type === "permission_mode")).toEqual([]);
	expect(frames.filter((frame) => frame.type === "drift_note").map((frame) => [frame.surface, frame.name]))
		.toContainEqual(["sdk_init", "permissionMode"]);
});

test("destination configuration enables only the browser the destination user opted into", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "ciao-configuration-"));
	resources.push(() => fs.rmSync(root, { recursive: true, force: true }));
	fs.writeFileSync(path.join(root, ".claude.json"), JSON.stringify({ claudeInChromeDefaultEnabled: true }));
	const { journal } = await startWorker([], undefined, undefined, undefined, { CLAUDE_CONFIG_DIR: root }, true);
	await eventually(() => journal().options !== null);
	expect(journal().options.extraArgs.chrome).toBeNull();
	expect(journal().options.extraArgs["replay-user-messages"]).toBeNull();
});

test("destination configuration keeps an explicit browser opt-in without global configuration", async () => {
	const { journal } = await startWorker([], undefined, undefined, undefined,
		{ CLAUDE_CODE_ENABLE_CFC: "true" }, true);
	await eventually(() => journal().options !== null);
	expect(journal().options.extraArgs.chrome).toBeNull();
});

test("destination configuration keeps an explicit browser opt-out", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "ciao-configuration-"));
	resources.push(() => fs.rmSync(root, { recursive: true, force: true }));
	fs.writeFileSync(path.join(root, ".claude.json"), JSON.stringify({ claudeInChromeDefaultEnabled: true }));
	const { journal } = await startWorker([], undefined, undefined, undefined,
		{ CLAUDE_CONFIG_DIR: root, CLAUDE_CODE_ENABLE_CFC: "0" }, true);
	await eventually(() => journal().options !== null);
	expect(Object.hasOwn(journal().options.extraArgs, "chrome")).toBe(false);
});

test.each(CONFIGURATION.rejected_sources)("destination configuration rejects unsupported launch policy %s before SDK startup", async (source) => {
	const { child, journal, frames } = await startWorker([], undefined, undefined, undefined,
		{ [CONFIGURATION.environment_key]: source });
	expect(await child.exited).toBe(2);
	expect(journal().options).toBeNull();
	expect(frames).toEqual([]);
});

test("rollback to a pre-contract daemon retains its isolated configuration", async () => {
	const { journal, frames } = await startWorker([], undefined, undefined, undefined,
		{ [CONFIGURATION.environment_key]: undefined, CLAUDE_CODE_ENABLE_CFC: "1" }, true);
	await eventually(() => journal().options !== null && frames.some((frame) => frame.type === "register"));
	expect(journal().options.settingSources).toEqual(CONFIGURATION.legacy_absent_source.settingSources);
	expect(journal().options.systemPrompt).toBe(CONFIGURATION.legacy_absent_source.systemPrompt);
	expect(Object.hasOwn(journal().options.extraArgs, "chrome")).toBe(CONFIGURATION.legacy_absent_source.chrome);
});

test.each([
	["opt-out", JSON.stringify({ claudeInChromeDefaultEnabled: false }), null],
	["absent", "{}", null],
	["unknown shape", JSON.stringify({ claudeInChromeDefaultEnabled: "future" }), "claudeInChromeDefaultEnabled"],
	["invalid", "{", "global_config_unreadable"],
	["invalid root", "null", "global_config_unreadable"],
	["oversized", " ".repeat(1024 * 1024 + 1), "global_config_unreadable"],
])("destination configuration handles %s browser preference without inventing an opt-in", async (_, content, diagnostic) => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "ciao-configuration-"));
	resources.push(() => fs.rmSync(root, { recursive: true, force: true }));
	fs.writeFileSync(path.join(root, ".claude.json"), content!);
	const { journal, frames, child } = await startWorker([], undefined, undefined, undefined,
		{ CLAUDE_CONFIG_DIR: root });
	expect(await child.exited).toBe(VENDOR_ENDED_UNPROMPTED_EXIT);
	expect(journal().options).not.toBeNull();
	expect(Object.hasOwn(journal().options.extraArgs, "chrome")).toBe(false);
	const notes = frames.filter((frame) => frame.type === "drift_note" && frame.surface === "configuration");
	expect(notes.map((frame) => frame.name)).toEqual(diagnostic ? [diagnostic] : []);
});

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
	// Nothing is missing, so the history is complete: the escape-heavy row is cut to what its
	// frame holds and says so, instead of taking every older row down with it.
	expect(registration.history_complete).toBe(true);
	const snapshot = frames.filter((frame) => frame.type === "snapshot_entry") as any[];
	expect(snapshot.map((frame) => frame.entry.source_id)).toEqual([
		"user-before-escaped-frame",
		"user-escaped-frame",
		"user-after-escaped-frame",
	]);
	const escaped = snapshot[1];
	expect(Buffer.byteLength(JSON.stringify(escaped))).toBeLessThanOrEqual(64 * 1024);
	expect(escaped.entry.body.text.length).toBeGreaterThan(0);
	expect(escaped.entry.truncation).toEqual({
		truncated: true,
		reason_code: "adapter_bound",
		original_bytes: 16 * 1024,
	});
	expect(snapshot[2].entry.body.text).toBe("Newest safe entry.");
});

/// Resumed history is mapped before `registered` says which daemon this is. A daemon that keeps
/// whole messages gets them whole, exactly as it does live; one that granted nothing larger
/// gets the head it validates, with the loss named.
test("resumed history is whole for a granting daemon and a named head for one that is not", async () => {
	const long = "h".repeat(100 * 1024);
	const history = (): HistoryFixture => ({
		sessionID: "11111111-2222-4333-8444-555555555555",
		fileSize: 256 * 1024,
		messages: [
			{
				type: "assistant",
				uuid: "long-reply",
				message: { role: "assistant", id: "msg-long", content: [{ type: "text", text: long }] },
			},
		],
	});
	const granting = await startWorker([], undefined, history(), undefined, undefined, false, {
		grant: 2 * 1024 * 1024,
	});
	await eventually(() => granting.frames.some((frame) => frame.type === "snapshot_end"));
	const whole = granting.frames.find((frame) => frame.type === "snapshot_entry") as any;
	expect(whole.entry.body.text).toBe(long);
	expect(whole.entry.truncation).toEqual({ truncated: false });

	const older = await startWorker([], undefined, history());
	await eventually(() => older.frames.some((frame) => frame.type === "snapshot_end"));
	const head = older.frames.find((frame) => frame.type === "snapshot_entry") as any;
	expect(head.entry.body.text).toBe(long.slice(0, 48 * 1024));
	expect(head.entry.truncation).toEqual({
		truncated: true,
		reason_code: "adapter_bound",
		original_bytes: 100 * 1024,
	});
	const registration = older.frames.find((frame) => frame.type === "register") as any;
	expect(registration.history_complete).toBe(true);
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

/// The host maps the same Claude transcript itself — for an attached session, and for a managed
/// one whose transcript is past this worker's reader bound — and the two must draw one
/// conversation identically. The shared fixture is the contract; the host's claude_history
/// tests read the same file. The reader filter here is the pinned SDK's documented one for a
/// linear chain: user and assistant records that are neither meta, sidechain nor team traffic,
/// projected to its SessionMessage shape.
/// The fixture writes long strings compactly; the host's harness expands them identically.
function expandFixture(value: any): any {
	if (Array.isArray(value)) return value.map(expandFixture);
	if (value !== null && typeof value === "object") {
		if (Array.isArray(value.$repeat)) return String(value.$repeat[0]).repeat(value.$repeat[1]);
		if (Array.isArray(value.$concat)) return value.$concat.map(expandFixture).join("");
		return Object.fromEntries(Object.entries(value).map(([key, field]) => [key, expandFixture(field)]));
	}
	return value;
}

test("canonical history matches the shared Claude transcript fixture", async () => {
	const fixture = expandFixture(
		JSON.parse(
			fs.readFileSync(
				path.join(import.meta.dir, "../../../protocol/fixtures/phase5/claude-history-v1.json"),
				"utf8",
			),
		),
	);
	const messages = fixture.records
		.filter(
			(record: any) =>
				(record.type === "user" || record.type === "assistant") &&
				typeof record.uuid === "string" &&
				!record.isMeta &&
				!record.isSidechain &&
				!record.teamName,
		)
		.map((record: any) => ({
			type: record.type,
			uuid: record.uuid,
			session_id: record.sessionId,
			message: record.message,
			parent_tool_use_id: null,
			parent_agent_id: null,
			timestamp: record.timestamp,
		}));
	// A granting daemon, so what arrives is the mapping itself rather than a head cut for an
	// older one: the fixture pins the mapping.
	const { frames } = await startWorker(
		[],
		undefined,
		{
			sessionID: "11111111-2222-4333-8444-555555555555",
			fileSize: 256 * 1024,
			createdAt: fixture.created_at_ms,
			messages,
		},
		undefined,
		undefined,
		false,
		{ grant: 2 * 1024 * 1024 },
	);
	await eventually(() => frames.some((frame) => frame.type === "snapshot_end"));

	const registration = frames.find((frame) => frame.type === "register") as Record<string, any>;
	expect(registration.history_complete).toBe(true);
	const entries = frames
		.filter((frame) => frame.type === "snapshot_entry")
		.map((frame) => (frame as any).entry);
	expect(entries).toEqual(
		fixture.expected.map(({ managed_source, attached_source, ...entry }: any) => ({
			source_id: managed_source,
			...entry,
		})),
	);
	expect(JSON.stringify(entries)).not.toContain("never forwarded");
	expect(JSON.stringify(entries)).not.toContain("Omitted synthetic reasoning");
});

test("the worker observes child identities across the parent result without forwarding child content", async () => {
	const { child, frames } = await startWorker([
		{ hook_event_name: "SubagentStart", agent_id: "private-child" },
		{ type: "result", subtype: "success" },
		{ type: "assistant", parent_tool_use_id: "tool-id", message: { id: "private-child-message", content: [{ type: "text", text: "private-child-reply" }] } },
		{ hook_event_name: "Notification", agent_id: "private-child", notification_type: "permission_prompt" },
		{ hook_event_name: "PostToolUse", agent_id: "private-child" },
		{ hook_event_name: "SubagentStop", agent_id: "private-child", last_assistant_message: "private-child-output" },
	]);
	expect(await child.exited).toBe(VENDOR_ENDED_UNPROMPTED_EXIT);
	const states = frames.filter(f => f.type === "child_activity" || f.type === "turn");
	const report = (f: Record<string, unknown>) => f.report as { state: string; ids: string[] } | undefined;
	expect(states.map(f => report(f)?.state ?? f.state)).toEqual(["started", "completed", "waiting", "progress", "finished"]);
	expect(report(states[0])?.ids).toEqual(report(states.at(-1)!)?.ids);
	expect(JSON.stringify(frames)).not.toContain("private-child");
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
			type: "user",
			isReplay: true,
			uuid: "u4",
			message: { content: "Another Claude session sent a message:\n\nThe notes are in." },
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

test("a Code Mode inner Bash call streams normally and still requires a permission decision", async () => {
	const input = { command: "echo probe-ok" };
	const { frames, send } = await startWorker([
		{ type: "assistant", message: { content: [{ type: "tool_use", id: "inner-bash", name: "Bash", input }] } },
		{ type: "user", message: { content: [{ type: "tool_result", tool_use_id: "inner-bash", content: "probe-ok" }] } },
		{ type: "result", subtype: "success" },
	], { tool: "Bash", input }, undefined, undefined, { CIAO_MANAGED_CODE_MODE: "1" });

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
	expect(raised.interaction.body).toContain("echo probe-ok");

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
	await eventually(() => frames.some((frame: any) => frame.entry?.body.tool?.result_preview === "probe-ok"));
	const calls = frames.filter((frame: any) => frame.entry?.source_id === "tool-inner-bash") as any[];
	expect(calls.map(frame => frame.entry.body.tool.status)).toEqual(["running", "complete"]);
	expect(calls[0].entry.body.tool.name).toBe("Bash");
});

// Suggestions are vendor proposals, not permission grants. In particular, the candidate SDK's
// changed Always-allow offering must not change Ciao's request-scoped Allow once / Deny contract.
const broadPermissionSuggestions = [
	{ type: "addRules", rules: [{ toolName: "Bash", ruleContent: "*" }], behavior: "allow", destination: "localSettings" },
	{ type: "addDirectories", directories: ["/synthetic"], destination: "session" },
	{ type: "setMode", mode: "acceptEdits", destination: "session" },
];

for (const [label, options] of [
	["absent", {}],
	["empty", { suggestions: [] }],
	["nonempty", { suggestions: broadPermissionSuggestions }],
] satisfies Array<[string, Pick<PermissionFixture, "suggestions">]>) {
	test(`permission suggestions ${label}: allow once, repeat deny and abort remain request scoped`, async () => {
		const input = { command: "printf synthetic" };
		const requests = ["first", "repeat", "aborted"].map((id) => ({
			tool: "Bash", input, toolUseID: `toolu_${id}`, ...options,
		}));
		const { frames, send, journal } = await startWorker(
			[], { requests, concurrent: false }, undefined, undefined, undefined, true, { runtime: "node" },
		);
		const cards = () => frames.filter((frame: any) => frame.type === "upsert_interaction") as any[];
		const answer = (commandID: string, interactionID: string, choiceID: string) => send({
			v: 1, type: "command", kind: "interaction_response", command_id: commandID,
			interaction_id: interactionID, choice_id: choiceID,
		});
		const receipt = (id: string) => frames.find((frame: any) => frame.type === "command_receipt" && frame.command_id === id) as any;
		const checkCard = (index: number) => {
			const card = cards()[index].interaction;
			expect(card.kind).toBe("permission");
			expect(card.title).toBe("Run Bash");
			expect(card.body).toBe(input.command);
			expect(card.response_schema.choices).toEqual([
				{ choice_id: "allow-once", label: "Allow once", scope: "once" },
				{ choice_id: "deny", label: "Deny", scope: "request" },
			]);
			return card.interaction_id;
		};
		await eventually(() => cards().length === 1);
		const firstID = checkCard(0);
		answer("allow-first", firstID, "allow-once");
		await eventually(() => cards().length === 2 && journal().permissionDecisions.length === 1);
		expect(receipt("allow-first")).toMatchObject({ state: "applied", evidence: "permission_resolved" });
		expect(journal().permissionDecisions).toEqual([{ toolUseID: "toolu_first", decision: { behavior: "allow" } }]);

		// Same tool and input asks again. A stale answer cannot resolve this new callback, and
		// the SDK receives neither rewritten input nor updatedPermissions to persist a rule.
		const repeatID = checkCard(1);
		expect(repeatID).not.toBe(firstID);
		answer("duplicate-first", firstID, "allow-once");
		await eventually(() => Boolean(receipt("duplicate-first")));
		expect(receipt("duplicate-first")).toMatchObject({ state: "rejected", reason_code: "already_resolved" });
		expect(journal().permissionDecisions).toHaveLength(1);
		answer("deny-repeat", repeatID, "deny");
		await eventually(() => cards().length === 3 && journal().permissionDecisions.length === 2);
		expect(receipt("deny-repeat")).toMatchObject({ state: "applied", evidence: "permission_resolved" });
		expect(journal().permissionDecisions[1]).toEqual({ toolUseID: "toolu_repeat", decision: { behavior: "deny", message: "Denied from Ciao." } });

		const abortedID = checkCard(2);
		send({ v: 1, type: "command", kind: "interrupt", command_id: "interrupt-pending" });
		await eventually(() => journal().permissionDecisions.length === 3 && Boolean(receipt("interrupt-pending")));
		expect(receipt("interrupt-pending")).toMatchObject({ state: "applied", evidence: "interrupt_receipt" });
		expect(journal().permissionDecisions[2]).toEqual({ toolUseID: "toolu_aborted", decision: { behavior: "deny", message: "Interrupted before a decision." } });
		answer("late-after-abort", abortedID, "allow-once");
		await eventually(() => Boolean(receipt("late-after-abort")));
		expect(receipt("late-after-abort")).toMatchObject({ state: "rejected", reason_code: "already_resolved" });
		expect(frames.filter((frame) => frame.type === "resolve_interaction").map((frame) => [frame.interaction_id, frame.resolution])).toEqual([
			[firstID, "applied"], [repeatID, "applied"], [abortedID, "expired"],
		]);
		expect(journal().permissionRequests).toEqual(requests.map(({ tool, input, toolUseID }) => ({ tool, input, toolUseID })));
		expect(journal().permissionDecisions).toHaveLength(3);
	});
}

for (const runtime of [process.execPath, "node"]) {
	for (const timing of ["preabort", "abortDuringAttach", "abortThenAnswer", "answerThenAbort"] as const) {
		test(`permission cancellation ${timing} settles once and detaches on ${path.basename(runtime)}`, async () => {
			const h = await startWorker([], {
				tool: "Bash", input: { command: "synthetic" }, toolUseID: "toolu_cancel",
				preabort: timing === "preabort", abortDuringAttach: timing === "abortDuringAttach",
				abortAfterAnswer: timing === "answerThenAbort",
			}, undefined, undefined, undefined, true, { runtime });
			const cards = () => h.frames.filter((f: any) => f.type === "upsert_interaction").map((f: any) => f.interaction);
			const receipt = (id: string) => h.frames.find((f: any) => f.type === "command_receipt" && f.command_id === id);
			if (timing === "preabort" || timing === "abortDuringAttach") {
				await eventually(() => h.journal().permissionDecisions?.length === 1);
				expect(cards()).toEqual([]);
				expect(h.frames.filter((f) => f.type === "resolve_interaction")).toEqual([]);
			} else {
				await eventually(() => cards().length === 1);
				const id = cards()[0].interaction_id;
				if (timing === "abortThenAnswer") {
					h.send({ type: "command", command_id: "cancel", kind: "interrupt" });
					await eventually(() => Boolean(receipt("cancel")));
					expect(receipt("cancel")).toMatchObject({ state: "applied", evidence: "interrupt_receipt" });
				}
				h.send({ type: "command", command_id: "answer", kind: "interaction_response", interaction_id: id, choice_id: "allow-once" });
				await eventually(() => Boolean(receipt("answer")) && h.journal().permissionDecisions.length === 1);
				expect(receipt("answer")).toMatchObject(timing === "abortThenAnswer"
					? { state: "rejected", reason_code: "already_resolved" }
					: { state: "applied", evidence: "permission_resolved" });
				h.send({ type: "command", command_id: "again", kind: "interrupt" });
				await eventually(() => Boolean(receipt("again")));
				expect(h.frames.filter((f) => f.type === "resolve_interaction")).toEqual([
					expect.objectContaining({ interaction_id: id, resolution: timing === "abortThenAnswer" ? "expired" : "applied" }),
				]);
			}
			expect(h.journal().permissionDecisions).toEqual([{ toolUseID: "toolu_cancel", decision: timing === "answerThenAbort"
				? { behavior: "allow" } : { behavior: "deny", message: "Interrupted before a decision." } }]);
			expect(h.journal().permissionListeners).toEqual([0]);
		});
	}
}

const unsupportedPermissions: PermissionFixture[] = [
	...[null, 1, "scalar", true, [], ["item"]].map((input) => ({ tool: "Bash", input })),
	...[null, 42, {}, [], "", "bad name", "a/b", "x".repeat(65), "Bash\\n"].map((tool) => ({ tool, input: {} })),
	...(["cycle", "bigint", "getter", "toJSON", "deep", "oversized"] as const).map((inputKind) => ({ tool: "Bash", input: {}, inputKind })),
];
for (const [index, request] of unsupportedPermissions.entries()) {
	test(`unrepresentable permission ${index} blocks with only explicit safe decisions`, async () => {
		const h = await startWorker([], { ...request, toolUseID: "toolu_unsupported" }, undefined, undefined, undefined, true);
		await eventually(() => h.frames.some((f) => f.type === "upsert_interaction"));
		const card = (h.frames.find((f) => f.type === "upsert_interaction") as any).interaction;
		expect(card.kind).toBe("unsupported");
		expect(card.response_schema.choices.map((c: any) => c.choice_id)).toEqual(["deny", "stop"]);
		expect(h.journal().permissionDecisions).toEqual([]);
		const answer = (command_id: string, choice_id: string) => h.send({ type: "command", kind: "interaction_response", command_id, interaction_id: card.interaction_id, choice_id });
		const receipt = (id: string) => h.frames.find((f: any) => f.type === "command_receipt" && f.command_id === id);
		answer("crafted", "allow-once");
		await eventually(() => Boolean(receipt("crafted")));
		expect(receipt("crafted")).toMatchObject({ state: "rejected", reason_code: "answer_shape_mismatch" });
		expect(h.journal().permissionDecisions).toEqual([]);
		const action = index % 3;
		if (action === 2) h.send({ type: "command", kind: "interrupt", command_id: "safe" });
		else answer("safe", action === 0 ? "deny" : "stop");
		await eventually(() => Boolean(receipt("safe")) && h.journal().permissionDecisions.length === 1);
		expect(receipt("safe")).toMatchObject({ state: "applied", evidence: action === 2 ? "interrupt_receipt" : "permission_resolved" });
		expect(h.journal().permissionDecisions).toEqual([{ toolUseID: "toolu_unsupported", decision: action === 2
			? { behavior: "deny", message: "Interrupted before a decision." }
			: { behavior: "deny", message: "Denied from Ciao.", ...(action === 1 ? { interrupt: true } : {}) } }]);
		expect(h.journal().permissionListeners).toEqual([0]);
		answer("late", "allow-once");
		await eventually(() => Boolean(receipt("late")));
		expect(receipt("late")).toMatchObject({ state: "rejected", reason_code: "already_resolved" });
		expect(h.frames.filter((f) => f.type === "resolve_interaction")).toEqual([
			expect.objectContaining({ interaction_id: card.interaction_id, resolution: action === 2 ? "expired" : "applied" }),
		]);
	});
}

for (const runtime of [process.execPath, "node"]) {
	for (const inputKind of ["proxy", "nestedProxy", "arrayProxy", "revoked", "nestedRevoked"] as const) {
		test(`proxy permission ${inputKind} never invokes traps on ${path.basename(runtime)}`, async () => {
			const h = await startWorker([], {
				requests: ["deny", "stop", "cancel"].map(toolUseID => ({ tool: "Bash", input: {}, inputKind, toolUseID })), concurrent: false,
			}, undefined, undefined, undefined, true, { runtime });
			const cards = () => h.frames.filter(f => f.type === "upsert_interaction").map((f: any) => f.interaction);
			const receipt = (id: string) => h.frames.find(f => f.type === "command_receipt" && f.command_id === id);
			for (const [index, action] of ["deny", "stop", "cancel"].entries()) {
				await eventually(() => cards().length === index + 1);
				const card = cards()[index];
				expect(card.kind).toBe("unsupported");
				expect(card.response_schema.choices).toEqual([
					{ choice_id: "deny", label: "Deny", scope: "request" },
					{ choice_id: "stop", label: "Stop", scope: "request" },
				]);
				const answer = (command_id: string, choice_id: string) => h.send({ type: "command", kind: "interaction_response", command_id, interaction_id: card.interaction_id, choice_id });
				answer(`forged-${action}`, "allow-once");
				await eventually(() => Boolean(receipt(`forged-${action}`)));
				expect(receipt(`forged-${action}`)).toMatchObject({ state: "rejected", reason_code: "answer_shape_mismatch" });
				expect(h.journal().permissionDecisions).toHaveLength(index);
				if (action === "cancel") h.send({ type: "command", kind: "interrupt", command_id: action });
				else answer(action, action);
				await eventually(() => Boolean(receipt(action)) && h.journal().permissionDecisions.length === index + 1);
				expect(receipt(action)).toMatchObject({ state: "applied", evidence: action === "cancel" ? "interrupt_receipt" : "permission_resolved" });
				expect(h.journal().permissionDecisions[index]).toEqual({ toolUseID: action, decision: action === "cancel"
					? { behavior: "deny", message: "Interrupted before a decision." }
					: { behavior: "deny", message: "Denied from Ciao.", ...(action === "stop" ? { interrupt: true } : {}) } });
				answer(`late-${action}`, "allow-once");
				await eventually(() => Boolean(receipt(`late-${action}`)));
				expect(receipt(`late-${action}`)).toMatchObject({ state: "rejected", reason_code: "already_resolved" });
				expect(h.frames.filter(f => f.type === "resolve_interaction" && f.interaction_id === card.interaction_id)).toEqual([
					expect.objectContaining({ resolution: action === "cancel" ? "expired" : "applied" }),
				]);
			}
			expect(h.journal().proxyTraps).toEqual([]);
			expect(h.journal().permissionListeners).toEqual([0, 0, 0]);
			expect(h.child.exitCode).toBeNull();
		});
	}
}

test("permission representation honors exact byte, token and nesting bounds", async () => {
	const byteLimit = 16 * 1024;
	const overhead = Buffer.byteLength(JSON.stringify({ value: "" }));
	const nested = (depth: number): unknown => {
		let value: unknown = null;
		for (let i = 0; i < depth; i++) value = { nested: value };
		return value;
	};
	for (const [request, kind] of [
		[{ tool: "x".repeat(64), input: { value: "x".repeat(byteLimit - overhead) } }, "permission"],
		[{ tool: "Bash", input: { value: "x".repeat(byteLimit - overhead + 1) } }, "unsupported"],
		[{ tool: "Bash", input: { value: "é".repeat((byteLimit - overhead) / 2) } }, "permission"],
		[{ tool: "Bash", input: { value: "é".repeat((byteLimit - overhead) / 2) + "x" } }, "unsupported"],
		[{ tool: "Bash", input: nested(64) }, "permission"],
		[{ tool: "Bash", input: nested(65) }, "unsupported"],
	] as const) {
		const h = await startWorker([], request);
		await eventually(() => h.frames.some((f) => f.type === "upsert_interaction"));
		const card = (h.frames.find((f) => f.type === "upsert_interaction") as any).interaction;
		expect(card.kind).toBe(kind);
		h.send({ type: "command", kind: "interaction_response", command_id: "deny-bound", interaction_id: card.interaction_id, choice_id: "deny" });
		await eventually(() => h.journal().permissionDecisions.length === 1);
		expect(h.journal().permissionDecisions[0].decision.behavior).toBe("deny");
	}
});

test("unknown but representable tool tokens are not a vendor allowlist", async () => {
	const h = await startWorker([], { tool: "mcp__future_server__new_tool", input: { nested: [null, true, 1, { value: "synthetic" }] }, suggestions: { malformed: true } });
	await eventually(() => h.frames.some((f) => f.type === "upsert_interaction"));
	const card = (h.frames.find((f) => f.type === "upsert_interaction") as any).interaction;
	expect(card.kind).toBe("permission");
	h.send({ type: "command", kind: "interaction_response", command_id: "allow", interaction_id: card.interaction_id, choice_id: "allow-once" });
	await eventually(() => h.journal().permissionDecisions.length === 1);
	expect(h.journal().permissionDecisions[0].decision).toEqual({ behavior: "allow" });
});

test("concurrent permissions resolve only their exact callback, out of order", async () => {
	const { frames, send, journal } = await startWorker([], {
		concurrent: true,
		requests: [
			{ tool: "Bash", input: { command: "printf first" }, toolUseID: "toolu_bash", suggestions: broadPermissionSuggestions },
			{ tool: "Write", input: { file_path: "/synthetic/second", content: "second" }, toolUseID: "toolu_write", suggestions: broadPermissionSuggestions },
		],
	}, undefined, undefined, undefined, true, { runtime: "node" });
	await eventually(() => frames.filter((frame) => frame.type === "upsert_interaction").length === 2);
	const cards = frames.filter((frame) => frame.type === "upsert_interaction") as any[];
	const bash = cards.find((frame) => frame.interaction.title === "Run Bash").interaction;
	const write = cards.find((frame) => frame.interaction.title === "Run Write").interaction;
	expect(bash.interaction_id).not.toBe(write.interaction_id);
	const answer = (id: string, choice: string, commandID: string) => send({
		v: 1, type: "command", kind: "interaction_response", command_id: commandID,
		interaction_id: id, choice_id: choice,
	});
	answer("unknown-interaction", "allow-once", "unknown");
	await eventually(() => frames.some((frame) => frame.type === "command_receipt" && frame.command_id === "unknown"));
	expect(frames.find((frame) => frame.type === "command_receipt" && frame.command_id === "unknown")).toMatchObject({ state: "rejected", reason_code: "already_resolved" });
	expect(journal().permissionDecisions).toEqual([]);
	answer(write.interaction_id, "allow-once", "allow-write");
	await eventually(() => journal().permissionDecisions.length === 1);
	expect(journal().permissionDecisions).toEqual([{ toolUseID: "toolu_write", decision: { behavior: "allow" } }]);
	// Even a fabricated persistent choice fails closed; vendor suggestions never mint one.
	answer(bash.interaction_id, "always-allow", "refuse-broad-choice");
	await eventually(() => journal().permissionDecisions.length === 2);
	expect(journal().permissionDecisions[1]).toEqual({ toolUseID: "toolu_bash", decision: { behavior: "deny", message: "Denied from Ciao." } });
	expect(frames.filter((frame) => frame.type === "resolve_interaction").map((frame) => frame.interaction_id)).toEqual([write.interaction_id, bash.interaction_id]);
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
	// A daemon from before the bridge grant validates nothing past the phone's head, so for it
	// the worker still cuts — and names the cut in the host's own vocabulary, with the size.
	expect(finished[1].entry.body.text.length).toBe(48 * 1024);
	expect(finished[1].entry.truncation).toEqual({
		truncated: true,
		reason_code: "adapter_bound",
		original_bytes: 50 * 1024,
	});
});

test("a daemon that grants its bridge bound gets every finished message whole", async () => {
	const overText = "o".repeat(300 * 1024);
	const { frames } = await startWorker(
		[
			{ type: "user", isReplay: true, uuid: "u1", message: { content: "p".repeat(70 * 1024) } },
			{
				type: "assistant",
				uuid: "a2",
				message: { id: "m2", content: [{ type: "text", text: overText }] },
			},
			{ type: "result", subtype: "success" },
		],
		undefined,
		undefined,
		undefined,
		undefined,
		false,
		{ grant: 2 * 1024 * 1024 },
	);
	await eventually(() =>
		frames.some((frame) => frame.type === "turn" && frame.state === "completed"),
	);
	const entries = frames.filter((frame) => frame.type === "upsert_entry") as any[];
	const user = entries.find((frame) => frame.entry.kind === "user_message");
	expect(user.entry.body.text).toBe("p".repeat(70 * 1024));
	const reply = entries.find((frame) => frame.entry.kind === "assistant_message");
	expect(reply.entry.body.text).toBe(overText);
	expect(reply.entry.truncation).toEqual({ truncated: false });
});

test("an escape-heavy reply is cut to what the frame holds instead of vanishing", async () => {
	const hostile = "\u0001".repeat(40 * 1024);
	const { frames } = await startWorker([
		{ type: "user", isReplay: true, uuid: "u1", message: { content: "go" } },
		{
			type: "assistant",
			uuid: "a1",
			message: { id: "m1", content: [{ type: "text", text: hostile }] },
		},
		{ type: "result", subtype: "success" },
	]);
	await eventually(() =>
		frames.some((frame) => frame.type === "turn" && frame.state === "completed"),
	);
	const reply = frames.find(
		(frame) => frame.type === "upsert_entry" && (frame as any).entry.kind === "assistant_message",
	) as any;
	// It used to be dropped whole: its encoding outgrew the frame and writeFrame refused it.
	expect(reply).toBeDefined();
	expect(Buffer.byteLength(JSON.stringify(reply))).toBeLessThanOrEqual(64 * 1024);
	expect(reply.entry.body.text.length * 6).toBeGreaterThan(64 * 1024 - 1024);
	expect(reply.entry.truncation).toEqual({
		truncated: true,
		reason_code: "adapter_bound",
		original_bytes: 40 * 1024,
	});
});

test("a tool argument that fits its budget is whole, and a larger one still parses", async () => {
	const content = "y".repeat(3 * 1024);
	const huge = "z".repeat(40 * 1024);
	const { frames } = await startWorker([
		{ type: "user", isReplay: true, uuid: "u1", message: { content: "write" } },
		{
			type: "assistant",
			uuid: "a1",
			message: {
				id: "m1",
				content: [
					{ type: "tool_use", id: "tool-fits", name: "Write", input: { file_path: "/tmp/a", content } },
					{ type: "tool_use", id: "tool-big", name: "Write", input: { file_path: "/tmp/b", content: huge } },
				],
			},
		},
		{ type: "result", subtype: "success" },
	]);
	await eventually(() =>
		frames.some((frame) => frame.type === "turn" && frame.state === "completed"),
	);
	const tools = frames.filter(
		(frame) => frame.type === "upsert_entry" && (frame as any).entry.kind === "tool",
	) as any[];
	const fits = tools.find((frame) => frame.entry.source_id === "tool-tool-fits");
	expect(JSON.parse(fits.entry.body.tool.input_preview).content).toBe(content);
	expect(fits.entry.truncation).toEqual({ truncated: false });
	const big = tools.find((frame) => frame.entry.source_id === "tool-tool-big");
	const parsed = JSON.parse(big.entry.body.tool.input_preview);
	expect(parsed.file_path).toBe("/tmp/b");
	expect(Buffer.byteLength(parsed.content)).toBeLessThanOrEqual(2048);
	expect(big.entry.truncation.reason_code).toBe("preview_bounded");
	expect(big.entry.truncation.original_bytes).toBeGreaterThan(40 * 1024);
});

// Node is the production interpreter; Bun is the CI runner and the historical test interpreter.
// Both must observe lost command input without waiting for queued snapshot writes to drain.
const WORKER_RUNTIMES = [
	["Bun", process.execPath],
	["Node", Bun.which("node") ?? "node"],
] as const;

function backpressuredHistory(): HistoryFixture {
	return {
		sessionID: "11111111-2222-4333-8444-555555555555",
		fileSize: 3 * 1024 * 1024,
		// Below both history bounds, but larger than a Unix socket's buffers. No sleeps or
		// scheduler luck are needed to leave writes pending while the daemon stops reading.
		messages: Array.from({ length: 80 }, (_, i) => ({
			type: "user",
			uuid: `history-${i}`,
			message: { role: "user", content: "x".repeat(32 * 1024) },
		})),
	};
}

test.each(WORKER_RUNTIMES)(
	"bridge EOF during a backpressured snapshot exits nonzero under %s",
	async (_, runtime) => {
		const { child, frames } = await startWorker(
			[],
			undefined,
			backpressuredHistory(),
			undefined,
			undefined,
			true,
			{ eofOnRegister: true, runtime },
		);
		await eventually(() => frames.some((frame) => frame.type === "register"));
		const registration = frames.find((frame) => frame.type === "register");
		expect(registration?.history_complete).toBe(true);
		await eventually(() => child.exitCode !== null);
		expect(child.exitCode).toBe(1);
	},
);

test.each(WORKER_RUNTIMES)(
	"an explicit host shutdown still exits cleanly under %s",
	async (_, runtime) => {
		const { child, frames, send } = await startWorker(
			[],
			undefined,
			backpressuredHistory(),
			undefined,
			undefined,
			true,
			{ runtime },
		);
		await eventually(() => frames.some((frame) => frame.type === "snapshot_end"));
		// The same history succeeds with a draining peer: exit 1 in the EOF case cannot be a
		// bad fixture, missing runtime, failed SDK import or an unconditionally failing worker.
		expect(frames.filter((frame) => frame.type === "snapshot_entry")).toHaveLength(80);
		expect(child.exitCode).toBe(null);
		send({ v: 1, type: "shutdown" });
		expect(await child.exited).toBe(0);
	},
);

// A takeover on a Linux host resumed a terminal's conversation, and the vendor answered with a
// result and ended its process before the phone had sent anything. The worker treated that as an
// ordinary end and exited 0, so the session read as one somebody stopped — and every Resume did
// the same thing again with nothing saying why. Both shapes the vendor can end in are covered:
// the error result followed by the SDK's throw, and a stream that simply runs out.
// What the pinned CLI said when it refused the Code Mode takeover, grounded 2026-11-26.
const CODE_MODE_REFUSAL = "Failed to resume session: This session was started in Code Mode (experimental), "
	+ "which isn't available because for now it only works in the interactive terminal, so it can't be resumed "
	+ "here. Resume it in the terminal: CLAUDE_CODE_EXPERIMENTAL_CODE_MODE=1 claude --resume private-session-id";
const VENDOR_ENDINGS = [
	["needs the headless Code Mode flag", "code_mode_terminal_only", [
		{ type: "result", subtype: "error_during_execution", is_error: true, errors: [
			"Failed to resume session: This session was started in Code Mode (experimental), which is off in this run, so it can't be resumed. To resume it, set CLAUDE_CODE_EXPERIMENTAL_CODE_MODE to 1 in the env block of --settings (the Agent SDK's settings option).",
		] },
	]],
	["throws after its error result", "vendor_ended_unprompted", [
		{ type: "result", subtype: "error_during_execution", is_error: true },
		{ fake_throw: "Claude Code process exited with code 1" },
	]],
	["runs out after its result", "vendor_ended_unprompted", [{ type: "result", subtype: "error_during_execution", is_error: true }]],
	// The vendor's reason arrives in the result's errors, or only in the stderr tail the SDK puts
	// on the error it throws; either names the failure.
	["refuses the resume in its result", "code_mode_terminal_only", [
		{ type: "result", subtype: "error_during_execution", is_error: true, errors: [CODE_MODE_REFUSAL] },
		{ fake_throw: "Claude Code process exited with code 1" },
	]],
	["refuses the resume on stderr", "code_mode_terminal_only", [
		{ type: "result", subtype: "error_during_execution", is_error: true },
		{ fake_throw: `Claude Code process exited with code 1\n${CODE_MODE_REFUSAL}` },
	]],
	["refuses another resume", "resume_refused", [{ fake_throw: "Failed to resume session: unavailable" }]],
	["cannot find the conversation", "resume_not_found", [
		{ fake_throw: "Claude Code process exited with code 1\nNo conversation found with session ID: private-session-id" },
	]],
] as const;
test.each(WORKER_RUNTIMES.flatMap(([name, runtime]) =>
	VENDOR_ENDINGS.map(([ending, cause, script]) => [ending, name, runtime, cause, script] as const)))(
	"a vendor that ends the session before its first prompt %s is a failed start under %s",
	async (_, __, runtime, cause, script) => {
		const { child, frames } = await startWorker(
			[...script], undefined, undefined, undefined, undefined, false, { runtime },
		);
		expect(await child.exited).toBe(exitFor(cause).code);
		// Names only: none of the vendor's words leave the worker.
		expect(JSON.stringify(frames)).not.toContain("private-session-id");
		expect(JSON.stringify(frames)).not.toContain("Code Mode");
		// The bridge still ends cleanly, so the only thing that changes is what the host records.
		expect(frames.at(-1)?.type).toBe("session_end");
	},
);

test("a queued prompt cannot disguise a Code Mode resume refusal", async () => {
	const { child, frames, send } = await startWorker([
		{ fake_await_prompt: true },
		{ fake_throw: CODE_MODE_REFUSAL },
	], undefined, undefined, undefined, { CIAO_MANAGED_RESUME_SESSION_ID: "synthetic-resume" });
	await eventually(() => frames.some(frame => frame.type === "snapshot_end"));
	send({ v: 1, type: "command", command_id: "early-prompt", kind: "prompt", text: "Hello" });
	expect(await child.exited).toBe(exitFor("code_mode_terminal_only").code);
});

// The grounded interrupt teardown stays an ordinary end: once the worker has handed the vendor a
// prompt, a turn ending in an error result and a nonzero CLI exit is how the pinned SDK stops.
test.each(WORKER_RUNTIMES)("a vendor that ends the session after a prompt keeps the clean teardown under %s", async (_, runtime) => {
	const { child, frames, send } = await startWorker([
		{ fake_await_prompt: true },
		{ type: "result", subtype: "error_during_execution", is_error: true },
		{ fake_throw: "Claude Code process exited with code 1" },
	], undefined, undefined, undefined, undefined, false, { runtime });
	await eventually(() => frames.some((frame) => frame.type === "snapshot_end"));
	send({ v: 1, type: "command", command_id: "command-interrupted", kind: "prompt", text: "Stop me." });
	expect(await child.exited).toBe(0);
	expect(frames.at(-1)?.type).toBe("session_end");
});

// A full peer close must also exit nonzero: error-only handling used to leave an invisible
// worker that could neither receive commands nor re-register with its consumed spawn token.
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

/// Spec 025: the daemon sends the whereabouts note with the prompt it belongs to, and Claude is
/// handed it through the SDK's own UserPromptSubmit hook as that prompt is read — never as part
/// of what the person said, and never with a later prompt.
test("the whereabouts note reaches Claude with its own prompt and no other", async () => {
	const { frames, send, journal } = await startWorker([], undefined, undefined, undefined, undefined, true);
	await eventually(() => frames.some((frame) => frame.type === "snapshot_end"));

	send({
		v: 1,
		type: "command",
		command_id: "command-away",
		kind: "prompt",
		text: "From the phone.",
		additional_context: "Where the user is: away from this Mac.",
	});
	send({ v: 1, type: "command", command_id: "command-plain", kind: "prompt", text: "Nothing owed." });
	await eventually(() => journal().promptContexts.length >= 2);

	expect(journal().promptContexts).toEqual([
		{ prompt: "From the phone.", context: "Where the user is: away from this Mac." },
		{ prompt: "Nothing owed.", context: null },
	]);
	// What the person said is exactly what they said: the note is not in the prompt text.
	expect(journal().promptContexts[0].prompt).not.toContain("Where the user is");
});
