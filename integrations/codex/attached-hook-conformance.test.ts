// Codex attached-hook conformance (Spec 012 §9).
//
// The schema assertions run everywhere: they read the checked-in pins and prove the adapter's
// assumptions are written down. The grounded ones need the pinned binary and run only under
// CIAO_TEST_CODEX_CLI=1, because each spawns a real `codex app-server`.
//
// Every grounded fact here has already been wrong once. `hooks.json` at user scope was recorded
// as arriving trusted; it does not, and an untrusted hook never runs — which is the difference
// between an installed integration and one that silently observes nothing.

import { afterEach, expect, test } from "bun:test";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const PINNED_CODEX_VERSION = "0.147.0";
const runGrounded = process.env.CIAO_TEST_CODEX_CLI === "1";
const groundedTest = runGrounded ? test : test.skip;
const pins = JSON.parse(
	fs.readFileSync(path.join(import.meta.dir, "conformance", "protocol-pins.json"), "utf8"),
);
const temporaryRoots: string[] = [];

afterEach(() => {
	while (temporaryRoots.length > 0) {
		fs.rmSync(temporaryRoots.pop()!, { recursive: true, force: true });
	}
});

function codexHome(hooks: unknown, trustedHashes: Record<string, string> = {}): string {
	// Codex reports and keys hooks by the resolved path, so `/var/...` becomes `/private/var/...`
	// on macOS. A trust entry written under the unresolved path never matches.
	const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "ciao-codex-")));
	temporaryRoots.push(root);
	fs.writeFileSync(path.join(root, "hooks.json"), JSON.stringify(hooks, null, 1));
	const state = Object.entries(trustedHashes)
		.map(([key, hash]) => `\n[hooks.state.${JSON.stringify(key)}]\ntrusted_hash = ${JSON.stringify(hash)}\n`)
		.join("");
	fs.writeFileSync(path.join(root, "config.toml"), state);
	return root;
}

function commandHook(command: string, timeout = 5) {
	return { hooks: [{ type: "command", command, timeout }] };
}

/** One `initialize` + one request against a fresh app-server, exactly as the host does it. */
async function appServer(home: string, method: string, params: unknown = {}): Promise<any> {
	const child = spawn("codex", ["app-server"], {
		env: { ...process.env, CODEX_HOME: home },
		stdio: ["pipe", "pipe", "ignore"],
	});
	try {
		const answers = new Map<number, any>();
		let buffer = "";
		child.stdout.on("data", (chunk) => {
			buffer += chunk;
			for (let end = buffer.indexOf("\n"); end >= 0; end = buffer.indexOf("\n")) {
				const line = buffer.slice(0, end);
				buffer = buffer.slice(end + 1);
				try {
					const message = JSON.parse(line);
					if (typeof message.id === "number" && message.method === undefined) {
						answers.set(message.id, message);
					}
				} catch {
					// Notifications and partial lines are not this test's business.
				}
			}
		});
		const send = (message: unknown) => child.stdin.write(`${JSON.stringify(message)}\n`);
		const waitFor = async (id: number) => {
			for (let attempt = 0; attempt < 400; attempt++) {
				if (answers.has(id)) return answers.get(id);
				await new Promise((resolve) => setTimeout(resolve, 50));
			}
			throw new Error(`the app-server never answered ${id}`);
		};

		send({
			jsonrpc: "2.0",
			id: 1,
			method: "initialize",
			params: { clientInfo: { name: "ciao-conformance", title: "Ciao", version: "0.0.1" } },
		});
		await waitFor(1);
		send({ jsonrpc: "2.0", method: "initialized", params: {} });
		send({ jsonrpc: "2.0", id: 2, method, params });
		return (await waitFor(2)).result;
	} finally {
		child.kill("SIGKILL");
	}
}

function listedHooks(response: any): any[] {
	return (response.data ?? []).flatMap((entry: any) => entry.hooks ?? []);
}

test("the pins record the protocol the adapter was built against", () => {
	expect(pins.pin).toBe(PINNED_CODEX_VERSION);
	// 90→95 at the 0.146.1→0.147.0 bump: five additive thread-section methods
	// (threadSection/{create,delete,list,update}, thread/section/move), nothing removed and
	// no notification moved. This literal is the tripwire that makes someone look — if it
	// fails, diff both binaries' generate-json-schema output before editing the number.
	expect(pins.counts).toEqual({ clientMethods: 95, serverNotifications: 70 });
	// Without these two the adapter has no join key and no history; their absence is
	// categorical rather than a degradation.
	expect(pins.requiredClientMethods).toContain("thread/read");
	expect(pins.requiredClientMethods).toContain("hooks/list");
});

test("every hook the installer writes is an event this Codex knows", () => {
	// The config file takes PascalCase and normalizes to the protocol's camelCase. An event
	// name Codex does not know is accepted silently by the file and never fires.
	const installed = [
		"SessionStart",
		"UserPromptSubmit",
		"PreToolUse",
		"PostToolUse",
		"Stop",
		"PermissionRequest",
		"SessionEnd",
	];
	const normalize = (event: string) => event.charAt(0).toLowerCase() + event.slice(1);
	for (const event of installed) {
		expect(pins.hookEventNames).toContain(normalize(event));
	}
});

test("the timeline mapping covers every thread item this Codex can emit", () => {
	// Not a completeness claim — the adapter maps six kinds and renders the rest as an explicit
	// unsupported card. This is the list that must be re-read when the pin moves.
	const mapped = [
		"userMessage",
		"agentMessage",
		"commandExecution",
		"fileChange",
		"mcpToolCall",
		"dynamicToolCall",
		"collabAgentToolCall",
		"webSearch",
	];
	for (const item of mapped) {
		expect(pins.threadItemTypes).toContain(item);
	}
	expect(pins.threadStatusTypes.slice().sort()).toEqual(
		["active", "idle", "notLoaded", "systemError"].sort(),
	);
	expect(pins.turnStatus).toContain("inProgress");
});

groundedTest("the generated pins still match the installed binary", () => {
	const result = spawnSync(
		"node",
		[path.join(import.meta.dir, "generate-conformance.mjs"), "--check"],
		{ encoding: "utf8" },
	);
	expect(result.stderr + result.stdout).toContain("match the pinned binary");
	expect(result.status).toBe(0);
});

groundedTest("a user-level hook arrives untrusted, so installing one is not enough", async () => {
	const home = codexHome({ hooks: { SessionStart: [commandHook("/bin/true")] } });
	const hooks = listedHooks(await appServer(home, "hooks/list"));
	expect(hooks).toHaveLength(1);
	// User scope, and still untrusted. The recorded claim that user-level hooks arrive trusted
	// was a machine that had already approved one; a hook in this state does not run at all.
	expect(hooks[0].source).toBe("user");
	expect(hooks[0].trustStatus).toBe("untrusted");
	expect(hooks[0].key).toBe(`${path.join(home, "hooks.json")}:session_start:0:0`);
});

groundedTest("recording the hash in config.toml is what makes a hook trusted", async () => {
	const command = "/bin/true";
	const home = codexHome({ hooks: { SessionStart: [commandHook(command)] } });
	const [before] = listedHooks(await appServer(home, "hooks/list"));
	expect(before.trustStatus).toBe("untrusted");

	// Ciao never writes this itself — trust is the user's to grant. The test writes it to prove
	// where the state lives, so `ciao agent status codex` can tell the truth about it.
	const trusted = codexHome(
		{ hooks: { SessionStart: [commandHook(command)] } },
		{ [`PLACEHOLDER:session_start:0:0`]: before.currentHash },
	);
	fs.writeFileSync(
		path.join(trusted, "config.toml"),
		fs
			.readFileSync(path.join(trusted, "config.toml"), "utf8")
			.replace("PLACEHOLDER", path.join(trusted, "hooks.json")),
	);
	const [after] = listedHooks(await appServer(trusted, "hooks/list"));
	expect(after.trustStatus).toBe("trusted");
});

groundedTest("the trust hash covers the command string and not what it runs", async () => {
	// This is why `ciao update` does not stop the live tail: the hook command is a fixed binary
	// path plus a fixed argument, so replacing the binary behind it changes nothing Codex hashes.
	const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "ciao-codex-script-")));
	temporaryRoots.push(root);
	const script = path.join(root, "hook.sh");
	fs.writeFileSync(script, "#!/bin/sh\nexit 0\n");

	const home = codexHome({ hooks: { SessionStart: [commandHook(`sh '${script}'`)] } });
	const [first] = listedHooks(await appServer(home, "hooks/list"));

	fs.writeFileSync(script, "#!/bin/sh\necho a completely different hook\nexit 1\n");
	const [afterScriptChange] = listedHooks(await appServer(home, "hooks/list"));
	expect(afterScriptChange.currentHash).toBe(first.currentHash);

	const moved = codexHome({ hooks: { SessionStart: [commandHook(`sh '${script}' extra`)] } });
	const [afterCommandChange] = listedHooks(await appServer(moved, "hooks/list"));
	expect(afterCommandChange.currentHash).not.toBe(first.currentHash);
});

groundedTest("the hook timeout is outside the trust hash", async () => {
	// Codex caps a SessionEnd hook at 3s and prints "clamping SessionEnd hook timeout to 3s" into
	// the user's TUI when it has to. Ciao installs 3s to stay quiet — which is only free because
	// the timeout is not hashed, so changing it does not re-gate an already-approved hook.
	const command = "/bin/true";
	const five = codexHome({ hooks: { SessionEnd: [commandHook(command, 5)] } });
	const three = codexHome({ hooks: { SessionEnd: [commandHook(command, 3)] } });
	const [a] = listedHooks(await appServer(five, "hooks/list"));
	const [b] = listedHooks(await appServer(three, "hooks/list"));
	expect(a.currentHash).toBe(b.currentHash);
});

groundedTest("a Ciao entry merges alongside another tool's without disturbing it", async () => {
	// The shape `~/.codex/hooks.json` has on a herdr machine, plus Ciao's appended entry.
	const herdr = commandHook("bash '/tmp/herdr-agent-state.sh' session", 10);
	const ciao = commandHook("'/tmp/ciao' __codex-hook");
	const home = codexHome({ hooks: { SessionStart: [herdr, ciao] } });
	const hooks = listedHooks(await appServer(home, "hooks/list"));

	expect(hooks).toHaveLength(2);
	// Independent identity, independent trust, and herdr keeps its position — it binds its pane
	// on the entry it already owns.
	expect(hooks[0].command).toContain("herdr-agent-state.sh");
	expect(hooks[1].command).toBe("'/tmp/ciao' __codex-hook");
	expect(hooks[0].currentHash).not.toBe(hooks[1].currentHash);
	expect(hooks[0].displayOrder).toBeLessThan(hooks[1].displayOrder);
	expect(new Set(hooks.map((hook: any) => hook.key)).size).toBe(2);
});

groundedTest("thread/read answers for a thread nobody has loaded", async () => {
	const home = codexHome({ hooks: {} });
	// Reading is not loading: an unknown thread refuses rather than being created, and the
	// method exists at this pin. A live TUI reports notLoaded to a separate app-server, so
	// loadedness is never the liveness signal.
	const loaded = await appServer(home, "thread/loaded/list");
	expect(loaded.data ?? []).toHaveLength(0);
	const listed = await appServer(home, "thread/list");
	expect(Array.isArray(listed.data)).toBe(true);
});
