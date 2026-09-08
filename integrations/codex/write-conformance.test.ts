// Codex write-surface conformance (Spec 013 §10).
//
// The schema assertions run everywhere: they read the checked-in pins and prove the adopted
// session's assumptions are written down. The grounded ones need the pinned binary and run only
// under CIAO_TEST_CODEX_CLI=1; none of them spends a model turn — the probes that do are
// hand-run in write-conformance/ and their results live in the ledger.

import { afterEach, expect, test } from "bun:test";
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

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

test("the write surface the adopted session calls is pinned", () => {
	// Any of these disappearing at a pin bump withdraws the write capabilities categorically
	// (Spec 013 §9); the pin is what makes that a reviewable diff instead of a runtime surprise.
	for (const method of [
		"thread/resume",
		"thread/archive",
		"turn/start",
		"turn/steer",
		"turn/interrupt",
	]) {
		expect(pins.requiredClientMethods).toContain(method);
	}
	expect(pins.steerRequiredParams).toEqual(["expectedTurnId", "input", "threadId"]);
	expect(pins.interruptRequiredParams).toEqual(["threadId", "turnId"]);
});

test("the approval requests and their decision sets are pinned", () => {
	for (const method of [
		"item/commandExecution/requestApproval",
		"item/fileChange/requestApproval",
		"item/tool/requestUserInput",
	]) {
		expect(pins.adoptedServerRequests).toContain(method);
	}
	// The card renders from the intersection of these with the vendor's runtime
	// `availableDecisions` (observed on the wire, not schema-declared at this pin). The three
	// Ciao understands must exist; a value beyond the pinned set is dropped, never guessed at.
	for (const decision of ["accept", "acceptForSession", "decline"]) {
		expect(pins.commandExecutionDecisions).toContain(decision);
		expect(pins.fileChangeDecisions).toContain(decision);
	}
});

test("the notifications the adopted session maps are pinned", () => {
	expect(pins.adoptedNotifications).toEqual([
		"turn/started",
		"turn/completed",
		"item/started",
		"item/completed",
		"item/agentMessage/delta",
	]);
});

test("the Rust adapter, the checked-in pins, and the generator agree on one Codex version", () => {
	// generate-conformance.mjs --check needs the pinned binary, so CI cannot run it; what CI can
	// catch is the desync that check exists for: someone bumps PINNED_CODEX_VERSION in the
	// adapter and never regenerates the pins, leaving the adapter's assumptions asserted against
	// a schema nobody distilled. Three spellings of the version, one value.
	const adapterSource = fs.readFileSync(
		path.join(import.meta.dir, "..", "..", "crates", "ciao-host", "src", "codex_adapter.rs"),
		"utf8",
	);
	const generatorSource = fs.readFileSync(
		path.join(import.meta.dir, "generate-conformance.mjs"),
		"utf8",
	);
	const rustPin = adapterSource.match(/PINNED_CODEX_VERSION: &str = "([^"]+)"/)?.[1];
	const generatorPin = generatorSource.match(/const PINNED_CODEX_VERSION = "([^"]+)"/)?.[1];
	expect(rustPin).toBe(pins.pin);
	expect(generatorPin).toBe(pins.pin);
});

test("thread/start takes the sandbox as a mode string", () => {
	// Sending the SandboxPolicy object is refused with `unknown variant` (ledger 2026-08-04);
	// the param is the plain SandboxMode enum, and read-only is the value the approval gate
	// leans on.
	expect(pins.threadStartSandboxIsMode).toBe(true);
	expect(pins.sandboxModes).toEqual(["danger-full-access", "read-only", "workspace-write"]);
});

/**
 * One `initialize` + one request against a fresh app-server, returning the whole response
 * message — the write-surface tests assert on refusals, so errors are answers here, not
 * failures.
 */
async function appServerExchange(home: string, method: string, params: unknown): Promise<any> {
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
			params: { clientInfo: { name: "ciao-write-conformance", title: "Ciao", version: "0.0.1" } },
		});
		await waitFor(1);
		send({ jsonrpc: "2.0", method: "initialized", params: {} });
		send({ jsonrpc: "2.0", id: 2, method, params });
		return await waitFor(2);
	} finally {
		child.kill("SIGKILL");
	}
}

function emptyHome(): string {
	const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "ciao-codex-write-")));
	temporaryRoots.push(root);
	return root;
}

groundedTest("a thread with no rollout cannot be resumed", async () => {
	// Adoption applies only to conversations that exist on disk (ADR 006 §4 amendment): a
	// contentless or unknown thread is refused by name, which is what makes "the rollout
	// exists" a checkable precondition rather than a hope.
	const response = await appServerExchange(emptyHome(), "thread/resume", {
		threadId: "00000000-0000-7000-8000-000000000000",
	});
	expect(response.error).toBeDefined();
	expect(String(response.error.message)).toContain("no rollout found");
});

groundedTest("a steer with no thread behind it is refused, not absorbed", async () => {
	// The fence's stronger half — refusing a wrong id and naming the live turn — needs a real
	// turn and is hand-probed (ledger 2026-08-04). What runs unattended is the floor: steer
	// never succeeds against nothing, so a phone send can never silently vanish.
	const response = await appServerExchange(emptyHome(), "turn/steer", {
		threadId: "00000000-0000-7000-8000-000000000000",
		expectedTurnId: "turn-nothing",
		input: [{ type: "text", text: "into the void" }],
	});
	expect(response.error).toBeDefined();
});

groundedTest("interrupt against an unknown thread is refused, not absorbed", async () => {
	const response = await appServerExchange(emptyHome(), "turn/interrupt", {
		threadId: "00000000-0000-7000-8000-000000000000",
		turnId: "turn-nothing",
	});
	expect(response.error).toBeDefined();
});
