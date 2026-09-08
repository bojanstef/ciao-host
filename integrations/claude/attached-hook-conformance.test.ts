import { afterEach, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const PINNED_CLAUDE_VERSION = "2.1.222";
const runGrounded = process.env.CIAO_TEST_CLAUDE_CLI === "1";
const groundedTest = runGrounded ? test : test.skip;
const temporaryRoots: string[] = [];

afterEach(() => {
	while (temporaryRoots.length > 0) {
		fs.rmSync(temporaryRoots.pop()!, { recursive: true, force: true });
	}
});

function temporaryRoot(prefix: string): string {
	const root = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
	temporaryRoots.push(root);
	fs.mkdirSync(path.join(root, "config"));
	fs.mkdirSync(path.join(root, "work"));
	return root;
}

// Markers Claude sets for its own children. Inherited from a shell that is itself inside a
// Claude session they name the wrong session, and every identity assertion below then reads a
// parent that has nothing to do with the run under test. Cleared rather than trusted, because
// the owner now develops Ciao from inside Ciao and would otherwise be the only one seeing this
// suite fail.
const INHERITED_SESSION_MARKERS = [
	"CLAUDECODE",
	"CLAUDE_CODE_ENTRYPOINT",
	"CLAUDE_CODE_SESSION_ID",
	"CLAUDE_CODE_CHILD_SESSION",
	"CLAUDE_CODE_BRIDGE_SESSION_ID",
	"CLAUDE_CODE_EXECPATH",
	"CLAUDE_PID",
];

function claude(root: string, args: string[], environment: Record<string, string> = {}) {
	const inherited = { ...process.env };
	for (const marker of INHERITED_SESSION_MARKERS) delete inherited[marker];
	return spawnSync("claude", args, {
		cwd: path.join(root, "work"),
		env: {
			...inherited,
			CLAUDE_CONFIG_DIR: path.join(root, "config"),
			DISABLE_AUTOUPDATER: "1",
			...environment,
		},
		encoding: "utf8",
		timeout: 30_000,
	});
}

function writeProbe(root: string): string {
	const probe = path.join(root, "probe.mjs");
	fs.writeFileSync(
		probe,
		String.raw`import fs from "node:fs";
let input = "";
for await (const chunk of process.stdin) {
  input += chunk;
  if (Buffer.byteLength(input, "utf8") > 65536) process.exit(64);
}
const value = JSON.parse(input);
let controllingTty = true;
try {
  const descriptor = fs.openSync("/dev/tty", "r");
  fs.closeSync(descriptor);
} catch {
  controllingTty = false;
}
const output = {
  event: value.hook_event_name,
  source: value.source ?? null,
  common_keys: Object.keys(value).sort(),
  session_id_uuid: typeof value.session_id === "string" && /^[0-9a-f-]{36}$/i.test(value.session_id),
  env_session_matches: process.env.CLAUDE_CODE_SESSION_ID === value.session_id,
  claude_pid_numeric: /^\d+$/.test(process.env.CLAUDE_PID ?? ""),
  direct_parent_matches: String(process.ppid) === process.env.CLAUDE_PID,
  child_session_marker: process.env.CLAUDE_CODE_CHILD_SESSION === "1",
  claudecode_marker: process.env.CLAUDECODE === "1",
  controlling_tty: controllingTty,
  transcript_absolute: typeof value.transcript_path === "string" && value.transcript_path.startsWith("/"),
  cwd_absolute: typeof value.cwd === "string" && value.cwd.startsWith("/"),
  plugin_root_matches: process.env.CIAO_EXPECTED_PLUGIN_ROOT === undefined || process.env.CLAUDE_PLUGIN_ROOT === process.env.CIAO_EXPECTED_PLUGIN_ROOT,
  prompt_id_present: typeof value.prompt_id === "string" && value.prompt_id.length > 0,
  prompt_matches: process.env.CIAO_EXPECTED_PROMPT === undefined || value.prompt === process.env.CIAO_EXPECTED_PROMPT,
};
fs.writeFileSync(process.env.CIAO_PROBE_OUTPUT, JSON.stringify(output));
`,
	);
	return probe;
}

function commandHook(probe: string) {
	return {
		type: "command",
		command: process.execPath,
		args: [probe],
		timeout: 10,
	};
}

test("Claude conformance remains pinned explicitly", () => {
	expect(PINNED_CLAUDE_VERSION).toMatch(/^\d+\.\d+\.\d+$/);
});

groundedTest("pinned Claude CLI exposes authenticated exec-form hook identity", () => {
	const root = temporaryRoot("ciao-claude-hook-");
	const probe = writeProbe(root);
	const resultFile = path.join(root, "result.json");
	const settingsFile = path.join(root, "settings.json");
	fs.writeFileSync(
		settingsFile,
		JSON.stringify({
			hooks: {
				SessionStart: [
					{ matcher: "startup", hooks: [commandHook(probe)] },
				],
			},
		}),
	);

	const version = spawnSync("claude", ["--version"], { encoding: "utf8" });
	expect(version.status).toBe(0);
	expect(version.stdout.trim()).toBe(`${PINNED_CLAUDE_VERSION} (Claude Code)`);

	const run = claude(
		root,
		["--settings", settingsFile, "--setting-sources", "user", "--init-only"],
		{ CIAO_PROBE_OUTPUT: resultFile },
	);
	expect(run.status).toBe(0);
	expect(run.stdout).toBe("");
	expect(run.stderr).toBe("");

	const result = JSON.parse(fs.readFileSync(resultFile, "utf8"));
	expect(result).toMatchObject({
		event: "SessionStart",
		source: "startup",
		session_id_uuid: true,
		env_session_matches: true,
		claude_pid_numeric: true,
		direct_parent_matches: true,
		child_session_marker: true,
		claudecode_marker: true,
		controlling_tty: false,
		transcript_absolute: true,
		cwd_absolute: true,
		plugin_root_matches: true,
	});
	expect(result.common_keys).toEqual([
		"cwd",
		"hook_event_name",
		"session_id",
		"source",
		"transcript_path",
	]);
});

// `UserPromptSubmit` is the only source of a user message in an attached timeline, and the two
// fields Ciao's parser requires from it -- `prompt` and `prompt_id` -- had no coverage at all,
// because every test above reaches only `SessionStart` through `--init-only`. Losing this event
// costs more than a timeline entry: without a `user_message` the conversation cannot be named or
// taken over, and nothing backfills it. The hook fires before the model is called, so this holds
// whether or not the CLI is authenticated -- the run's exit status is deliberately not asserted.
groundedTest("pinned Claude CLI reports a submitted prompt with an identifier", () => {
	const root = temporaryRoot("ciao-claude-prompt-");
	const probe = writeProbe(root);
	const resultFile = path.join(root, "result.json");
	const settingsFile = path.join(root, "settings.json");
	const prompt = "Conformance probe: reply with exactly pong.";
	fs.writeFileSync(
		settingsFile,
		JSON.stringify({ hooks: { UserPromptSubmit: [{ hooks: [commandHook(probe)] }] } }),
	);

	claude(
		root,
		["--settings", settingsFile, "--setting-sources", "user", "-p", prompt],
		{ CIAO_PROBE_OUTPUT: resultFile, CIAO_EXPECTED_PROMPT: prompt },
	);

	const result = JSON.parse(fs.readFileSync(resultFile, "utf8"));
	expect(result).toMatchObject({
		event: "UserPromptSubmit",
		prompt_matches: true,
		prompt_id_present: true,
		session_id_uuid: true,
		env_session_matches: true,
		claude_pid_numeric: true,
		child_session_marker: true,
		claudecode_marker: true,
	});
	// Exact, like the SessionStart contract above: a field disappearing is what Ciao's parser
	// rejects the whole event over, and a new one is worth a deliberate look.
	expect(result.common_keys).toEqual([
		"cwd",
		"hook_event_name",
		"permission_mode",
		"prompt",
		"prompt_id",
		"session_id",
		"transcript_path",
	]);
});

groundedTest("personal skills-directory plugin loads without editing settings", () => {
	const root = temporaryRoot("ciao-claude-plugin-");
	const probe = writeProbe(root);
	const resultFile = path.join(root, "result.json");
	const plugin = path.join(root, "config", "skills", "ciao-probe");
	fs.mkdirSync(path.join(plugin, ".claude-plugin"), { recursive: true });
	fs.mkdirSync(path.join(plugin, "hooks"));
	fs.writeFileSync(
		path.join(plugin, ".claude-plugin", "plugin.json"),
		JSON.stringify({
			name: "ciao-probe",
			displayName: "Ciao Probe",
			version: "0.0.1",
			description: "Disposable Ciao attached-hook conformance probe",
			author: { name: "Ciao" },
			license: "MIT OR Apache-2.0",
		}),
	);
	fs.writeFileSync(
		path.join(plugin, "hooks", "hooks.json"),
		JSON.stringify({
			hooks: {
				SessionStart: [
					{ matcher: "startup", hooks: [commandHook(probe)] },
				],
			},
		}),
	);

	const validation = claude(root, ["plugin", "validate", plugin, "--strict"]);
	expect(validation.status).toBe(0);

	const run = claude(root, ["--setting-sources", "user", "--init-only"], {
		CIAO_PROBE_OUTPUT: resultFile,
		CIAO_EXPECTED_PLUGIN_ROOT: plugin,
	});
	expect(run.status).toBe(0);
	expect(run.stdout).toBe("");
	expect(run.stderr).toBe("");
	expect(JSON.parse(fs.readFileSync(resultFile, "utf8"))).toMatchObject({
		event: "SessionStart",
		plugin_root_matches: true,
		claude_pid_numeric: true,
		direct_parent_matches: true,
	});
});
