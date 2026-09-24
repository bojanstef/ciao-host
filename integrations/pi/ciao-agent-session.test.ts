import { afterEach, describe, expect, mock, test } from "bun:test";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
mock.module("@earendil-works/pi-coding-agent", () => ({ VERSION: "0.81.1" }));
const {
	CiaoAgentBridge,
	defaultBridgeSocketPath,
	encodeBridgeFrame,
	fitEntryFrame,
	detectPiCommandSurface,
	isPiMajorCompatible,
	isTestedPiVersion,
	mapSessionBranch,
	registerCiaoAgentExtension,
	truncateUtf8,
} = await import("./ciao-agent-session.ts");

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
			const value = JSON.parse(buffer.subarray(4, length + 4).toString("utf8"));
			buffer = buffer.subarray(length + 4);
			onValue(value);
		}
	};
}

async function eventually(predicate: () => boolean, timeout = 2_000): Promise<void> {
	const deadline = Date.now() + timeout;
	while (!predicate()) {
		if (Date.now() >= deadline) throw new Error("timed_out");
		await Bun.sleep(10);
	}
}

test("a tested build is the conformance minor, not every build that works", () => {
	expect(isTestedPiVersion("0.81.1")).toBe(true);
	// The routine upgrade that used to strand native control.
	expect(isTestedPiVersion("0.81.9")).toBe(true);
	// Older patch: the tested build may need something added after it.
	expect(isTestedPiVersion("0.81.0")).toBe(false);
	expect(isTestedPiVersion("0.82.0")).toBe(false);
	expect(isTestedPiVersion("0.81.2-rc1")).toBe(false);
});

test("only a declared breaking change closes the door", () => {
	expect(isPiMajorCompatible("0.82.1")).toBe(true);
	expect(isPiMajorCompatible("0.99.0")).toBe(true);
	expect(isPiMajorCompatible("1.0.0")).toBe(false);
	expect(isPiMajorCompatible("garbage")).toBe(false);
});

test("the command surface is detected, so a rename disables what it removed", () => {
	const pi = { sendUserMessage() {} };
	const ctx = { mode: "tui" as const, isIdle: () => true, abort() {} };
	const present = detectPiCommandSurface(pi, ctx);
	expect(present.send).toBe(true);
	expect(present.abort).toBe(true);

	// A future Pi that renames the send API keeps interrupt working and loses messaging,
	// which a version pin could only express as "all of it, off".
	const renamed = detectPiCommandSurface({} as never, ctx);
	expect(renamed.send).toBe(false);
	expect(renamed.abort).toBe(true);

	// Losing abort leaves messaging intact.
	expect(detectPiCommandSurface(pi, { ...ctx, abort: undefined } as never).send).toBe(true);
	expect(detectPiCommandSurface(pi, { ...ctx, abort: undefined } as never).abort).toBe(false);

	// Outside a TUI nothing is offered, whatever exists.
	expect(detectPiCommandSurface(pi, { ...ctx, mode: "headless" } as never).send).toBe(false);
	expect(detectPiCommandSurface(undefined, undefined).send).toBe(false);
});

describe("bounded Pi mapping", () => {
	test("UTF-8 bounds never split a scalar", () => {
		expect(truncateUtf8("éé", 3)).toEqual({ text: "é", truncated: true, originalBytes: 4 });
		expect(truncateUtf8("ok", 2)).toEqual({ text: "ok", truncated: false, originalBytes: 2 });
	});

	test("platform paths use only Ciao's documented per-user layout", () => {
		expect(defaultBridgeSocketPath("darwin", {}, "/Users/tester")).toBe(
			"/Users/tester/Library/Application Support/Ciao/run/agent.sock",
		);
		// The state directory, never XDG_RUNTIME_DIR, matching `CiaoPaths::for_linux_home`. This
		// used to assert the opposite and so pinned the bug: a supervised daemon has no
		// XDG_RUNTIME_DIR while the operator's shell does, and the two dialled different sockets.
		expect(defaultBridgeSocketPath("linux", { XDG_RUNTIME_DIR: "/run/user/42" }, "/home/tester")).toBe(
			"/home/tester/.local/state/ciao/run/agent.sock",
		);
		expect(
			defaultBridgeSocketPath(
				"linux",
				{ XDG_RUNTIME_DIR: "/run/user/42", XDG_STATE_HOME: "/custom/state" },
				"/home/tester",
			),
		).toBe("/custom/state/ciao/run/agent.sock");
		expect(defaultBridgeSocketPath("linux", { XDG_STATE_HOME: "relative" }, "/home/tester")).toBe(
			"/home/tester/.local/state/ciao/run/agent.sock",
		);
	});

	test("snapshot mapping omits thinking and metadata, merges tools, and never invokes getters", () => {
		let getterInvoked = false;
		const hostileArgs = Object.create(null);
		Object.defineProperty(hostileArgs, "secret", {
			enumerable: true,
			get() {
				getterInvoked = true;
				return "must-not-run";
			},
		});
		const branch = [
			{
				type: "message",
				id: "m1",
				parentId: null,
				timestamp: "2026-07-23T00:00:00Z",
				message: { role: "user", content: "hello", timestamp: 1_753_228_800_000 },
			},
			{
				type: "message",
				id: "m2",
				parentId: "m1",
				timestamp: "2026-07-23T00:00:01Z",
				message: {
					role: "assistant",
					content: [
						{ type: "thinking", thinking: "hidden" },
						{ type: "text", text: "visible" },
						{ type: "toolCall", id: "tool-1", name: "read", arguments: hostileArgs },
					],
					stopReason: "toolUse",
					timestamp: 1_753_228_801_000,
				},
			},
			{
				type: "message",
				id: "m3",
				parentId: "m2",
				timestamp: "2026-07-23T00:00:02Z",
				message: {
					role: "toolResult",
					toolCallId: "tool-1",
					toolName: "read",
					content: [{ type: "text", text: "result" }],
					isError: false,
					timestamp: 1_753_228_802_000,
				},
			},
			{
				type: "model_change",
				id: "meta",
				parentId: "m3",
				timestamp: "2026-07-23T00:00:03Z",
				provider: "private",
				modelId: "private",
			},
		] as any;

		const mapped = mapSessionBranch(branch);
		expect(getterInvoked).toBe(false);
		expect(mapped.map((entry) => entry.kind)).toEqual(["user_message", "assistant_message", "tool"]);
		expect(JSON.stringify(mapped)).not.toContain("hidden");
		expect(JSON.stringify(mapped)).not.toContain("private");
		const tool = mapped.find((entry) => entry.kind === "tool");
		expect(tool?.body.type).toBe("tool");
		if (tool?.body.type === "tool") {
			expect(tool.body.tool.result_preview).toBe("result");
			expect(tool.body.tool.input_preview).toContain("[accessor]");
		}
	});
});

test("malformed daemon response reconnects without affecting the TUI context", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "ciao-pi-reconnect-"));
	const socketPath = path.join(root, "agent.sock");
	let connections = 0;
	const server = net.createServer((socket) => {
		connections += 1;
		socket.on(
			"data",
			decodeFrames((frame) => {
				if (frame.type !== "register") return;
				if (connections === 1) {
					socket.write(Buffer.from([0, 0, 0, 1, 0xff]));
				} else {
					socket.write(
						encodeBridgeFrame({
							v: 1,
							type: "registered",
							session_id: "0123456789abcdef0123456789abcdef",
							process_generation: 1,
							snapshot_epoch: 2,
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
	const bridge = new CiaoAgentBridge({} as any, socketPath);
	resources.push(async () => {
		bridge.stop(true);
		await new Promise<void>((resolve) => server.close(() => resolve()));
		fs.rmSync(root, { recursive: true, force: true });
	});
	bridge.start({
		mode: "tui",
		cwd: "/synthetic/workspace",
		isIdle: () => true,
		sessionManager: {
			getSessionId: () => "synthetic-session",
			getBranch: () => [],
		},
	} as any);

	await eventually(() => bridge.status() === "connected");
	expect(connections).toBe(2);
});

test("real framed socket correlates prompt receipts and deduplicates commands", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "ciao-pi-bridge-"));
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
						encodeBridgeFrame({
							v: 1,
							type: "registered",
							session_id: "0123456789abcdef0123456789abcdef",
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
	resources.push(async () => {
		peer?.destroy();
		await new Promise<void>((resolve) => server.close(() => resolve()));
		fs.rmSync(root, { recursive: true, force: true });
	});

	const handlers = new Map<string, Array<(event: any, ctx: any) => unknown>>();
	const sent: Array<{ text: string; options?: { deliverAs?: "steer" | "followUp" } }> = [];
	let context: any;
	let idle = true;
	let aborts = 0;
	const pi: any = {
		on(name: string, handler: (event: any, ctx: any) => unknown) {
			const values = handlers.get(name) ?? [];
			values.push(handler);
			handlers.set(name, values);
		},
		registerCommand() {},
		sendUserMessage(text: string, options?: { deliverAs?: "steer" | "followUp" }) {
			sent.push({ text, options });
			for (const handler of handlers.get("input") ?? []) {
				handler(
					{
						type: "input",
						text,
						source: "extension",
						streamingBehavior: options?.deliverAs,
					},
					context,
				);
			}
		},
	};
	const bridge = registerCiaoAgentExtension(pi, socketPath);
	resources.push(() => bridge.stop(true));
	context = {
		mode: "tui",
		cwd: "/private/workspace",
		isIdle: () => idle,
		abort() {
			aborts += 1;
		},
		sessionManager: {
			getSessionId: () => "upstream-session-id",
			getBranch: () => [
				{
					type: "message",
					id: "m1",
					parentId: null,
					timestamp: "2026-07-23T00:00:00Z",
					message: { role: "user", content: "fixture", timestamp: 1_753_228_800_000 },
				},
			],
		},
		ui: { notify() {} },
	};
	for (const handler of handlers.get("session_start") ?? []) {
		handler({ type: "session_start", reason: "startup" }, context);
	}
	await eventually(() => frames.some((frame) => frame.type === "snapshot_end"));
	const registration = frames.find((frame) => frame.type === "register");
	expect(registration?.adapter).toBe("pi");
	expect(registration?.mode).toBe("tui");
	expect(registration?.workspace_display).toBe("workspace");
	expect(JSON.stringify(registration)).not.toContain("/private/workspace");

	const command = {
		v: 1,
		type: "command",
		command_id: "11111111111111111111111111111111",
		kind: "prompt",
		text: "native prompt",
	};
	peer?.write(encodeBridgeFrame(command));
	await eventually(
		() =>
			frames.filter(
				(frame) => frame.type === "command_receipt" && frame.command_id === command.command_id,
			).length >= 2,
	);
	const receipts = frames.filter(
		(frame) => frame.type === "command_receipt" && frame.command_id === command.command_id,
	);
	expect(receipts.map((receipt) => receipt.state)).toEqual(["accepted", "applied"]);
	expect(receipts[1].evidence).toBe("pi_input_event");
	expect(sent).toEqual([{ text: "native prompt", options: undefined }]);

	peer?.write(encodeBridgeFrame(command));
	await eventually(
		() =>
			frames.filter(
				(frame) => frame.type === "command_receipt" && frame.command_id === command.command_id,
			).length >= 3,
	);
	expect(sent).toHaveLength(1);
	expect(
		frames.filter((frame) => frame.type === "command_receipt" && frame.command_id === command.command_id).at(-1)
			?.state,
	).toBe("applied");

	async function sendAndWait(
		next: Record<string, unknown>,
		count = 1,
	): Promise<Record<string, unknown>[]> {
		peer?.write(encodeBridgeFrame({ v: 1, type: "command", ...next }));
		await eventually(
			() =>
				frames.filter(
					(frame) => frame.type === "command_receipt" && frame.command_id === next.command_id,
				).length >= count,
		);
		return frames.filter(
			(frame) => frame.type === "command_receipt" && frame.command_id === next.command_id,
		);
	}

	idle = false;
	const steer = await sendAndWait(
		{
			command_id: "22222222222222222222222222222222",
			kind: "steer",
			text: "synthetic steer",
		},
		2,
	);
	const followUp = await sendAndWait(
		{
			command_id: "33333333333333333333333333333333",
			kind: "follow_up",
			text: "synthetic follow-up",
		},
		2,
	);
	const interrupt = await sendAndWait(
		{
			command_id: "44444444444444444444444444444444",
			kind: "interrupt",
		},
		2,
	);
	const busyPrompt = await sendAndWait({
		command_id: "55555555555555555555555555555555",
		kind: "prompt",
		text: "synthetic busy prompt",
	});
	idle = true;
	const idleSteer = await sendAndWait({
		command_id: "66666666666666666666666666666666",
		kind: "steer",
		text: "synthetic idle steer",
	});

	expect(steer.map((receipt) => receipt.state)).toEqual(["accepted", "applied"]);
	expect(followUp.map((receipt) => receipt.state)).toEqual(["accepted", "applied"]);
	expect(interrupt.map((receipt) => receipt.state)).toEqual(["accepted", "applied"]);
	expect(busyPrompt.at(-1)?.reason_code).toBe("agent_busy");
	expect(idleSteer.at(-1)?.reason_code).toBe("agent_not_active");
	expect(sent.slice(1)).toEqual([
		{ text: "synthetic steer", options: { deliverAs: "steer" } },
		{ text: "synthetic follow-up", options: { deliverAs: "followUp" } },
	]);
	expect(aborts).toBe(1);

	// Turn edges ride Pi's own idle flag, which is the same fact that decides `interrupt`, so the
	// phone's working row and its stop button can never disagree about whose turn it is.
	const turns = () => frames.filter((frame) => frame.type === "turn");
	const fire = (name: string, event: Record<string, unknown>) => {
		for (const handler of handlers.get(name) ?? []) handler({ type: name, ...event }, context);
	};

	// The command exchange above left a turn open. Settle it first, so what follows is a real
	// transition rather than a repeat — the distinction this dedupe exists to make.
	idle = true;
	fire("agent_end", {});
	await eventually(() => turns().at(-1)?.state === "completed");

	const settled = turns().length;
	idle = false;
	fire("agent_start", {});
	await eventually(() => turns().length > settled);
	const running = turns().at(-1);
	expect(running?.state).toBe("running");
	expect(running?.activity).toBe("thinking");
	expect(typeof running?.run_id).toBe("string");

	// A hook that fires while the agent is still working is not another edge; a chatty stream
	// must not churn revisions on the host.
	const afterRunning = turns().length;
	fire("message_update", { message: {} });
	expect(turns()).toHaveLength(afterRunning);

	idle = true;
	fire("agent_end", {});
	await eventually(() => turns().length > afterRunning);
	const completed = turns().at(-1);
	expect(completed?.state).toBe("completed");
	// The run that ended is the run that started, so the phone can tell turns apart.
	expect(completed?.run_id).toBe(running?.run_id);
});
describe("whole messages, sized for the daemon they reach", () => {
	const textEntry = (text: string) => ({
		source_id: "pi.message.fixture",
		source_revision: 1,
		timestamp: 1,
		state: "complete" as const,
		kind: "assistant_message" as const,
		body: { type: "text" as const, text },
		truncation: { truncated: false },
	});
	const frameBytes = (frame: unknown) => Buffer.byteLength(JSON.stringify(frame));

	test("a granting daemon gets the whole message; one that granted nothing gets a named cut", () => {
		const long = "Synthetic long reply, café 🦀. ".repeat(8_000);
		expect(Buffer.byteLength(long)).toBeGreaterThan(64 * 1024);
		const whole = fitEntryFrame("upsert_entry", textEntry(long), 2 * 1024 * 1024) as any;
		expect(whole.entry.body.text).toBe(long);
		expect(whole.entry.truncation).toEqual({ truncated: false });

		const legacy = fitEntryFrame("upsert_entry", textEntry(long)) as any;
		expect(Buffer.byteLength(legacy.entry.body.text)).toBeLessThanOrEqual(48 * 1024);
		expect(long.startsWith(legacy.entry.body.text)).toBe(true);
		expect(legacy.entry.truncation).toEqual({
			truncated: true,
			reason_code: "adapter_bound",
			original_bytes: Buffer.byteLength(long),
		});
		expect(frameBytes(legacy)).toBeLessThanOrEqual(64 * 1024);
	});

	test("an escape-heavy message is cut to what fits the frame instead of failing it", () => {
		const hostile = "\u0001".repeat(48 * 1024);
		const frame = fitEntryFrame("snapshot_entry", textEntry(hostile)) as any;
		expect(frameBytes(frame)).toBeLessThanOrEqual(64 * 1024);
		// As long as the frame allows, not cut to nothing.
		expect(frame.entry.body.text.length * 6).toBeGreaterThan(64 * 1024 - 1024);
		expect(frame.entry.truncation.reason_code).toBe("adapter_bound");
		expect(frame.entry.truncation.original_bytes).toBe(hostile.length);

		const tool = {
			...textEntry(""),
			kind: "tool" as const,
			body: {
				type: "tool" as const,
				tool: {
					name: "bash",
					status: "complete",
					input_preview: "\u0001".repeat(16 * 1024),
					result_preview: "\u0001".repeat(32 * 1024),
				},
			},
		};
		const shed = fitEntryFrame("upsert_entry", tool) as any;
		expect(frameBytes(shed)).toBeLessThanOrEqual(64 * 1024);
		expect(shed.entry.truncation.reason_code).toBe("preview_bounded");
	});

	test("a tool argument that fits its budget is sent whole, and a larger one still parses", () => {
		const content = "y".repeat(3 * 1024);
		const huge = "z".repeat(40 * 1024);
		const branch = [
			{
				type: "message",
				id: "m1",
				parentId: null,
				timestamp: "2026-09-23T00:00:00Z",
				message: {
					role: "assistant",
					content: [
						{ type: "toolCall", id: "tool-fits", name: "write", arguments: { path: "/tmp/a", content } },
						{ type: "toolCall", id: "tool-big", name: "write", arguments: { path: "/tmp/b", content: huge } },
					],
					stopReason: "toolUse",
					timestamp: 1_758_585_600_000,
				},
			},
		] as any;
		const tools = mapSessionBranch(branch).filter((entry) => entry.body.type === "tool") as any[];
		const fits = tools.find((entry) => JSON.parse(entry.body.tool.input_preview).path === "/tmp/a");
		expect(JSON.parse(fits.body.tool.input_preview).content).toBe(content);
		expect(fits.truncation).toEqual({ truncated: false });

		const big = tools.find((entry) => JSON.parse(entry.body.tool.input_preview).path === "/tmp/b");
		const parsed = JSON.parse(big.body.tool.input_preview);
		expect(Buffer.byteLength(parsed.content)).toBeLessThanOrEqual(2048);
		expect(big.truncation.reason_code).toBe("preview_bounded");
		expect(big.truncation.original_bytes).toBeGreaterThan(40 * 1024);
	});

	test("an extension asks for the larger bound, and falls back once when an old daemon refuses", async () => {
		const long = "Synthetic long user message, naïve. ".repeat(4_000);
		for (const daemon of ["current", "old"] as const) {
			const root = fs.mkdtempSync(path.join(os.tmpdir(), "ciao-pi-grant-"));
			const socketPath = path.join(root, "agent.sock");
			const registrations: Record<string, unknown>[] = [];
			const entries: any[] = [];
			const server = net.createServer((socket) => {
				socket.on(
					"data",
					decodeFrames((frame) => {
						if (frame.type === "snapshot_entry") entries.push(frame.entry);
						if (frame.type !== "register") return;
						registrations.push(frame);
						const asked = "frame_bytes" in frame;
						// An old daemon's strict register decoder refuses the field and hangs up.
						if (daemon === "old" && asked) return socket.destroy();
						socket.write(
							encodeBridgeFrame({
								v: 1,
								type: "registered",
								session_id: "0123456789abcdef0123456789abcdef",
								process_generation: 1,
								snapshot_epoch: 1,
								...(daemon === "current" && asked ? { frame_bytes: 2 * 1024 * 1024 } : {}),
							}),
						);
					}),
				);
			});
			await new Promise<void>((resolve, reject) => {
				server.once("error", reject);
				server.listen(socketPath, resolve);
			});
			const bridge = new CiaoAgentBridge({} as any, socketPath);
			resources.push(async () => {
				bridge.stop(true);
				await new Promise<void>((resolve) => server.close(() => resolve()));
				fs.rmSync(root, { recursive: true, force: true });
			});
			bridge.start({
				mode: "tui",
				cwd: "/synthetic/workspace",
				isIdle: () => true,
				sessionManager: {
					getSessionId: () => `synthetic-${daemon}`,
					getBranch: () => [
						{
							type: "message",
							id: "m1",
							parentId: null,
							timestamp: "2026-09-23T00:00:00Z",
							message: { role: "user", content: long, timestamp: 1_758_585_600_000 },
						},
					],
				},
			} as any);
			await eventually(() => entries.length > 0);
			expect(registrations[0].frame_bytes).toBe(2 * 1024 * 1024);
			if (daemon === "current") {
				expect(registrations).toHaveLength(1);
				expect(entries[0].body.text).toBe(long);
			} else {
				expect(registrations).toHaveLength(2);
				expect("frame_bytes" in registrations[1]).toBe(false);
				expect(Buffer.byteLength(entries[0].body.text)).toBeLessThanOrEqual(48 * 1024);
				expect(entries[0].truncation.reason_code).toBe("adapter_bound");
			}
		}
	});
});

/// A stand-in daemon on a Unix socket that can go away and come back on the same path, the way a
/// `ciao update` or `ciao setup` restart does. It grants the bridge bound to any register that
/// asks, as a current daemon does.
async function restartableDaemon(socketPath: string) {
	const registrations: Record<string, unknown>[] = [];
	const snapshotEnds: Record<string, unknown>[] = [];
	const sockets = new Set<net.Socket>();
	let server: net.Server | undefined;
	const start = async () => {
		server = net.createServer((socket) => {
			sockets.add(socket);
			socket.on("close", () => sockets.delete(socket));
			socket.on(
				"data",
				decodeFrames((frame) => {
					if (frame.type === "snapshot_end") snapshotEnds.push(frame);
					if (frame.type !== "register") return;
					registrations.push(frame);
					socket.write(
						encodeBridgeFrame({
							v: 1,
							type: "registered",
							session_id: "0123456789abcdef0123456789abcdef",
							process_generation: registrations.length,
							snapshot_epoch: 1,
							...("frame_bytes" in frame ? { frame_bytes: 2 * 1024 * 1024 } : {}),
						}),
					);
				}),
			);
		});
		await new Promise<void>((resolve, reject) => {
			server!.once("error", reject);
			server!.listen(socketPath, resolve);
		});
	};
	const stop = async () => {
		for (const socket of sockets) socket.destroy();
		await new Promise<void>((resolve) => server?.close(() => resolve()));
	};
	await start();
	return { registrations, snapshotEnds, start, stop };
}

function piContext(branch: unknown[] = []) {
	return {
		mode: "tui",
		cwd: "/synthetic/workspace",
		isIdle: () => true,
		sessionManager: {
			getSessionId: () => "synthetic-restart",
			getBranch: () => branch,
		},
	} as any;
}

test("a daemon restart does not cost the extension its grant", async () => {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), "ciao-pi-restart-"));
	const socketPath = path.join(root, "agent.sock");
	const daemon = await restartableDaemon(socketPath);
	const bridge = new CiaoAgentBridge({} as any, socketPath);
	resources.push(async () => {
		bridge.stop(true);
		await daemon.stop();
		fs.rmSync(root, { recursive: true, force: true });
	});
	bridge.start(piContext());
	await eventually(() => bridge.status() === "connected");
	expect(daemon.registrations[0].frame_bytes).toBe(2 * 1024 * 1024);

	// The daemon goes away. Every reconnect attempt while it is gone fails before a socket ever
	// connects — that is not a daemon refusing the ask, and must not be read as one.
	await daemon.stop();
	await eventually(() => bridge.status() === "connecting");
	await Bun.sleep(450);
	await daemon.start();
	await eventually(() => daemon.registrations.length >= 2, 5_000);
	expect(daemon.registrations[1].frame_bytes).toBe(2 * 1024 * 1024);
});
