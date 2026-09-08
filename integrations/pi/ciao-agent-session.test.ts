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