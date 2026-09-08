#!/usr/bin/env node
// Regenerates the Codex protocol pins from the pinned binary (Spec 012 §9).
//
// The whole schema is 39 files and mostly irrelevant to a read-only adapter. This distills the
// shapes the adapter actually depends on into one reviewable file, so a version bump produces a
// diff someone reads rather than a behaviour change nobody sees.
//
//   node integrations/codex/generate-conformance.mjs           # write the pins
//   node integrations/codex/generate-conformance.mjs --check   # fail if they moved
//
// Nothing here is hand-written. If a pin looks wrong, the binary changed.

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PINNED_CODEX_VERSION = "0.147.0";
const OUTPUT = path.join(import.meta.dirname, "conformance", "protocol-pins.json");

// A discriminant is spelled `const` for some variants and a one-value `enum` for others; the
// generator picks per variant, so both are read.
function discriminant(schema) {
	if (typeof schema?.const === "string") return schema.const;
	if (Array.isArray(schema?.enum) && schema.enum.length === 1) return schema.enum[0];
	return undefined;
}

// Key-sorted JSON, so a digest reflects the protocol rather than a hash map's mood.
export function canonical(value) {
	if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
	if (value && typeof value === "object") {
		return `{${Object.keys(value)
			.sort()
			.map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
			.join(",")}}`;
	}
	return JSON.stringify(value);
}

function methodsOf(document) {
	return document.oneOf
		.map((variant) => discriminant(variant.properties?.method))
		.filter((method) => typeof method === "string")
		.sort();
}

export function generate({ binary = "codex", expectedVersion = PINNED_CODEX_VERSION } = {}) {
	if (!/^\d+\.\d+\.\d+$/.test(expectedVersion)) throw new Error("expected a stable Codex version");
	const version = execFileSync(binary, ["--version"], { encoding: "utf8", timeout: 10_000, maxBuffer: 4096 }).trim();
	if (version !== `codex-cli ${expectedVersion}`) {
		throw new Error(`expected codex-cli ${expectedVersion}, found "${version}"`);
	}
	const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ciao-codex-schema-"));
	try {
		execFileSync(binary, ["app-server", "generate-json-schema", "--out", directory], {
			stdio: "ignore", timeout: 30_000,
		});
		const read = (name) => JSON.parse(fs.readFileSync(path.join(directory, name), "utf8"));
		const clientRequest = read("ClientRequest.json");
		const serverNotification = read("ServerNotification.json");
		const serverRequest = read("ServerRequest.json");
		const definitions = serverNotification.definitions;

		const clientMethods = methodsOf(clientRequest);
		const serverMethods = methodsOf(serverNotification);
		const serverRequestMethods = methodsOf(serverRequest);
		const variantsOf = (name) =>
			(definitions[name].oneOf ?? definitions[name].anyOf ?? [])
				.map((variant) => discriminant(variant.properties?.type))
				.filter(Boolean)
				.sort();

		// The params schema for one client method, `$ref`s resolved against the document's own
		// definitions — the generator inlines some and references others, so both are read.
		const paramsOf = (method) => {
			const variant = clientRequest.oneOf.find(
				(candidate) => discriminant(candidate.properties?.method) === method,
			);
			let params = variant?.properties?.params ?? {};
			if (typeof params.$ref === "string") {
				params = clientRequest.definitions[params.$ref.split("/").pop()] ?? {};
			}
			return params;
		};

		// A decision enum from a server-request response schema: the authoritative set of answers
		// a client may send back. The runtime `availableDecisions` field narrows per request but is
		// not schema-declared at this pin, so the response enum is what gets pinned.
		const decisionsOf = (file, name) => {
			const document = read(file);
			return (document.definitions?.[name]?.oneOf ?? [])
				.map((variant) => (Array.isArray(variant.enum) ? variant.enum[0] : variant.const))
				.filter((value) => typeof value === "string")
				.sort();
		};

		return {
			pin: expectedVersion,
			generatedBy: "integrations/codex/generate-conformance.mjs",
			counts: { clientMethods: clientMethods.length, serverNotifications: serverMethods.length },
			// The join key and the read the adapter depends on. Their absence is categorical.
			// Spec 013 widened the list with the adopted write surface: resume, the three turn
			// verbs, and archive. Any of these disappearing withdraws the write capabilities
			// categorically rather than degrading them.
			requiredClientMethods: [
				"thread/read",
				"thread/list",
				"hooks/list",
				"thread/resume",
				"thread/archive",
				"turn/start",
				"turn/steer",
				"turn/interrupt",
				// The model-surface read (2026-08-18): losing it withdraws the model/effort
				// capabilities categorically — the phone hides the picker rather than
				// showing one that does nothing. The write behind the picker,
				// `thread/settings/update`, is experimental and absent from the vendor's
				// schema export, so this filter can never pin it: its loss is handled at
				// runtime instead, as a rejected receipt per attempted change.
				"model/list",
			].filter((method) => clientMethods.includes(method)),
			// The server-initiated requests the adopted session answers (Spec 013 §6–§7); the
			// question card ships behind its own probe, but the shape is pinned with the rest.
			adoptedServerRequests: [
				"item/commandExecution/requestApproval",
				"item/fileChange/requestApproval",
				"item/tool/requestUserInput",
			].filter((method) => serverRequestMethods.includes(method)),
			// What a client may answer, from the response schemas — the authoritative decision
			// sets a permission card renders from (intersected at runtime with the request's
			// undeclared-but-observed `availableDecisions`).
			commandExecutionDecisions: decisionsOf(
				"CommandExecutionRequestApprovalResponse.json",
				"CommandExecutionApprovalDecision",
			),
			fileChangeDecisions: decisionsOf(
				"FileChangeRequestApprovalResponse.json",
				"FileChangeApprovalDecision",
			),
			// The notification set the adopted session maps into canonical entries (Spec 013 §6).
			adoptedNotifications: [
				"turn/started",
				"turn/completed",
				"item/started",
				"item/completed",
				"item/agentMessage/delta",
			].filter((method) => serverMethods.includes(method)),
			// The two fences the composer rides (Spec 013 §6): steer names the turn it expects,
			// interrupt names the turn it ends.
			steerRequiredParams: (paramsOf("turn/steer").required ?? []).slice().sort(),
			interruptRequiredParams: (paramsOf("turn/interrupt").required ?? []).slice().sort(),
			// `thread/start` takes the plain mode string, not the policy object — sending the
			// object is refused with `unknown variant` (ledger, 2026-08-04).
			threadStartSandboxIsMode: JSON.stringify(
				paramsOf("thread/start").properties?.sandbox ?? {},
			).includes("SandboxMode"),
			sandboxModes: (clientRequest.definitions?.SandboxMode?.enum ?? []).slice().sort(),
			hookEventNames: definitions.HookEventName.enum.slice().sort(),
			hookSources: definitions.HookSource.enum.slice().sort(),
			hookRunStatus: definitions.HookRunStatus.enum.slice().sort(),
			threadItemTypes: variantsOf("ThreadItem"),
			threadStatusTypes: variantsOf("ThreadStatus"),
			turnStatus: definitions.TurnStatus.enum.slice().sort(),
			threadActiveFlags: definitions.ThreadActiveFlag.enum.slice().sort(),
			// A digest of the whole emitted protocol. It changes for reasons this file does not
			// pin, which is the point: it says "look again" without failing every bump.
			//
			// Canonicalized first: the generator emits its aggregate schema from a hash map, so
			// two runs of the same binary order the definitions differently. A raw byte digest
			// would change on every run and mean nothing.
			schemaDigest: createHash("sha256")
				.update(
					fs
						.readdirSync(directory)
						.sort()
						.map((name) => {
							const full = path.join(directory, name);
							if (!fs.statSync(full).isFile()) return "";
							return `${name}\u0000${canonical(JSON.parse(fs.readFileSync(full, "utf8")))}\n`;
						})
						.join(""),
				)
				.digest("hex"),
		};
	} finally {
		fs.rmSync(directory, { recursive: true, force: true });
	}
}

// The pin artifact owns membership. A new field cannot become maintenance-only policy;
// generate-conformance.test.ts locks this selection to Rust's runtime carry check.
export function readSetChanges(baseline, candidate) {
	const provenance = new Set(["pin", "generatedBy", "counts", "schemaDigest"]);
	return Object.keys(baseline).filter(key => !provenance.has(key)
		&& canonical(baseline[key]) !== canonical(candidate[key])).sort();
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	const args = process.argv.slice(2);
	const inspect = args[0] === "--inspect";
	if (!(args.length === 0 || (args.length === 1 && args[0] === "--check")
		|| (inspect && args.length === 2))) {
		console.error("Usage: generate-conformance.mjs [--check | --inspect <stable-version>]");
		process.exit(2);
	}
	// Inspect only prints a candidate. It can never overwrite the checked-in grounding.
	const generated = `${JSON.stringify(generate(inspect ? { expectedVersion: args[1] } : {}), null, "\t")}\n`;
	if (inspect) {
		process.stdout.write(generated);
	} else if (args[0] === "--check") {
		if (fs.readFileSync(OUTPUT, "utf8") !== generated) {
			console.error("Codex protocol pins are stale. Run: node integrations/codex/generate-conformance.mjs");
			process.exit(1);
		}
		console.log("Codex protocol pins match the pinned binary.");
	} else {
		fs.mkdirSync(path.dirname(OUTPUT), { recursive: true });
		fs.writeFileSync(OUTPUT, generated);
		console.log(`Wrote ${path.relative(process.cwd(), OUTPUT)}`);
	}
}
