/**
 * Ciao attached Agent Session bridge for Pi 0.81.1.
 *
 * This extension observes only documented Pi session/lifecycle events and accepts only four
 * fixed native operations. It never intercepts extension UI, terminal input, arbitrary commands,
 * files, environment data, credentials, or terminal bytes.
 */

import net from "node:net";
import os from "node:os";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";
import {
	VERSION,
	type ExtensionAPI,
	type ExtensionContext,
	type SessionEntry,
} from "@earendil-works/pi-coding-agent";

const BRIDGE_VERSION = 1;
const TESTED_PI_VERSION = "0.81.1";

/// Whether the build is one conformance actually covered: the same minor, at or after the
/// tested patch. Reported to the host so it can say so; no longer what gates control.
export function isTestedPiVersion(version: string): boolean {
	const running = parseVersion(version);
	const tested = parseVersion(TESTED_PI_VERSION);
	if (!running || !tested) return false;
	return running[0] === tested[0] && running[1] === tested[1] && running[2] >= tested[2];
}

/// The vendor has not declared a breaking change. Detection below cannot see a surface that
/// still exists and has quietly changed meaning, which is what a major bump announces.
export function isPiMajorCompatible(version: string): boolean {
	const running = parseVersion(version);
	const tested = parseVersion(TESTED_PI_VERSION);
	return !!running && !!tested && running[0] === tested[0];
}

function parseVersion(text: string): [number, number, number] | undefined {
	const parts = text.split(".");
	if (parts.length !== 3) return undefined;
	const numbers = parts.map((part) => (/^\d+$/.test(part) ? Number(part) : Number.NaN));
	return numbers.some(Number.isNaN) ? undefined : (numbers as [number, number, number]);
}

/// What the bridge can actually do with the harness in front of it, found by looking rather
/// than by comparing a version string. A rename or removal is caught here on any build; a
/// version pin only ever caught it on a build someone had already tested.
///
/// Presence is checked, not behaviour. A surface that still exists and now means something
/// different is invisible to this, which is why `isPiMajorCompatible` still bounds it.
export function detectPiCommandSurface(
	pi: Pick<ExtensionAPI, "sendUserMessage"> | undefined,
	ctx: Pick<ExtensionContext, "mode" | "isIdle" | "abort"> | undefined,
): { send: boolean; deliverAs: boolean; abort: boolean; idle: boolean } {
	const idle = typeof ctx?.isIdle === "function";
	const send = typeof pi?.sendUserMessage === "function" && ctx?.mode === "tui" && idle;
	return {
		send,
		// `deliverAs` is a second argument. Pi declaring it with a default would report an
		// arity of one, so a narrower reading would strand steer and follow-up on a build
		// that supports them; presence of the function is the honest signal available.
		deliverAs: send,
		abort: typeof ctx?.abort === "function" && ctx?.mode === "tui" && idle,
		idle,
	};
}
const MAX_FRAME_BYTES = 64 * 1024;
// The socket writer is bounded independently from the host's per-phone 1 MiB Agent queue.
// It must accommodate one legal 4 MiB reconciliation snapshot plus bounded JSON overhead.
const MAX_PENDING_BYTES = 8 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024;
const MAX_SNAPSHOT_ENTRIES = 4096;
const MAX_TEXT_BYTES = 48 * 1024;
const MAX_INPUT_PREVIEW_BYTES = 16 * 1024;
const MAX_RESULT_PREVIEW_BYTES = 32 * 1024;
const MAX_PROMPT_BYTES = 32 * 1024;
const MAX_RECEIPTS = 128;
const LIVE_EMISSION_INTERVAL_MS = 50;
const MAX_RECONNECT_DELAY_MS = 5_000;
const PROCESS_NONCE_PROPERTY = "__ciaoAgentSessionProcessNonceV1";
const STRICT_UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

interface BridgeCommands {
	prompt: boolean;
	steer: boolean;
	follow_up: boolean;
	interrupt: boolean;
}

interface Truncation {
	truncated: boolean;
	reason_code?: string;
	original_bytes?: number;
}

interface ToolBody {
	name: string;
	status: string;
	input_preview?: string;
	result_preview?: string;
}

export interface BridgeEntry {
	source_id: string;
	source_revision: number;
	timestamp: number;
	state: "streaming" | "complete" | "failed";
	kind:
		| "user_message"
		| "assistant_message"
		| "tool"
		| "system"
		| "warning"
		| "error"
		| "unsupported";
	body:
		| { type: "text"; text: string }
		| { type: "tool"; tool: ToolBody }
		| { type: "unsupported"; reason_code: string };
	truncation: Truncation;
}

type WireObject = Record<string, unknown>;

type CommandKind = "prompt" | "steer" | "follow_up" | "interrupt";

interface BridgeCommand {
	v: 1;
	type: "command";
	command_id: string;
	kind: CommandKind;
	text?: string;
}

interface PendingApplication {
	commandId: string;
	text: string;
	expectedBehavior: "steer" | "followUp" | undefined;
	accepted: boolean;
	observed: boolean;
}

interface CachedReceipt {
	state: "accepted" | "applied" | "rejected";
	evidence?: string;
	reasonCode?: string;
}

interface Preview {
	text?: string;
	truncated: boolean;
	originalBytes?: number;
}

interface ToolState {
	name: string;
	input?: unknown;
	result?: unknown;
	isError: boolean;
	timestamp: number;
	complete: boolean;
}

interface PendingWrite {
	bytes: Buffer;
	onFlushed?: () => void;
}

function processNonce(): string {
	const root = globalThis as typeof globalThis & Record<string, unknown>;
	const existing = root[PROCESS_NONCE_PROPERTY];
	if (typeof existing === "string" && /^[0-9a-f]{32}$/.test(existing)) return existing;
	const nonce = randomBytes(16).toString("hex");
	root[PROCESS_NONCE_PROPERTY] = nonce;
	return nonce;
}

function isAbsoluteEnvironmentPath(value: string | undefined): value is string {
	return typeof value === "string" && value.length > 0 && path.isAbsolute(value);
}

/**
 * Mirrors Ciao's documented per-user runtime layout without accepting an arbitrary override.
 *
 * On Linux the socket follows the *state* directory and never `XDG_RUNTIME_DIR`, matching
 * `CiaoPaths::for_linux_home` — see the reasoning recorded there. This file used to prefer
 * `XDG_RUNTIME_DIR`, which is exactly the rule the host side had already abandoned: a daemon
 * supervised by cron or a non-lingering unit has no `XDG_RUNTIME_DIR` while the operator's
 * interactive shell does, so Pi dialled `/run/user/<uid>/ciao/agent.sock` while the daemon was
 * listening on `~/.local/state/ciao/run/agent.sock`. Nothing was there, the extension never
 * registered, and the phone showed the host with no agents running — with no error anywhere,
 * because a socket that does not exist is indistinguishable from a host that is simply idle.
 */
export function defaultBridgeSocketPath(
	platform = process.platform,
	environment: NodeJS.ProcessEnv = process.env,
	home = os.homedir(),
): string {
	if (platform === "linux") {
		const stateRoot = isAbsoluteEnvironmentPath(environment.XDG_STATE_HOME)
			? environment.XDG_STATE_HOME
			: path.join(home, ".local", "state");
		return path.join(stateRoot, "ciao", "run", "agent.sock");
	}
	return path.join(home, "Library", "Application Support", "Ciao", "run", "agent.sock");
}

function utf8Bytes(value: string): number {
	return Buffer.byteLength(value, "utf8");
}

export function truncateUtf8(value: string, maximumBytes: number): Preview {
	const originalBytes = utf8Bytes(value);
	if (originalBytes <= maximumBytes) {
		return { text: value, truncated: false, originalBytes };
	}
	const bytes = Buffer.from(value, "utf8");
	let end = maximumBytes;
	while (end > 0 && (bytes[end] & 0xc0) === 0x80) end -= 1;
	return {
		text: bytes.subarray(0, end).toString("utf8"),
		truncated: true,
		originalBytes,
	};
}

function safeToken(value: unknown, fallback: string): string {
	if (typeof value !== "string" || value.length === 0) return fallback;
	const normalized = value.replace(/[^0-9A-Za-z._-]/g, "_");
	const truncated = truncateUtf8(normalized, 64).text ?? "";
	return truncated.length > 0 ? truncated : fallback;
}

function sourceID(namespace: string, value: unknown): string {
	const source = typeof value === "string" || typeof value === "number" ? String(value) : "unknown";
	const digest = createHash("sha256").update(namespace).update("\0").update(source).digest("hex");
	return `pi.${namespace}.${digest.slice(0, 40)}`;
}

function timestampSeconds(value: unknown): number {
	const number = typeof value === "number" && Number.isFinite(value) ? Math.floor(value) : Date.now();
	return Math.max(1, number > 10_000_000_000 ? Math.floor(number / 1_000) : number);
}

function noTruncation(): Truncation {
	return { truncated: false };
}

function truncation(previews: Preview[]): Truncation {
	const truncated = previews.some((preview) => preview.truncated);
	if (!truncated) return noTruncation();
	const knownBytes = previews.reduce((total, preview) => total + (preview.originalBytes ?? 0), 0);
	return {
		truncated: true,
		reason_code: "adapter_bound",
		...(knownBytes > 0 ? { original_bytes: knownBytes } : {}),
	};
}

function textParts(content: unknown): string[] {
	if (typeof content === "string") return [content];
	if (!Array.isArray(content)) return [];
	const parts: string[] = [];
	for (const item of content) {
		if (isRecord(item) && item.type === "text" && typeof item.text === "string") {
			parts.push(item.text);
		}
	}
	return parts;
}

function textPreview(content: unknown, maximumBytes: number): Preview {
	const text = textParts(content).join("\n");
	if (text.length === 0) return { truncated: false };
	return truncateUtf8(text, maximumBytes);
}

/**
 * Produces a preview from bounded plain data only. Accessors, prototypes, functions, symbols,
 * cycles, and deep/large structures become categorical placeholders rather than being invoked.
 */
function jsonPreview(value: unknown, maximumBytes: number): Preview {
	let nodes = 0;
	let structurallyTruncated = false;
	const seen = new WeakSet<object>();

	const copy = (candidate: unknown, depth: number): unknown => {
		nodes += 1;
		if (nodes > 1_024 || depth > 8) {
			structurallyTruncated = true;
			return "[bounded]";
		}
		if (
			candidate === null ||
			typeof candidate === "string" ||
			typeof candidate === "boolean"
		) {
			return candidate;
		}
		if (typeof candidate === "number") return Number.isFinite(candidate) ? candidate : "[number]";
		if (typeof candidate === "bigint") return "[bigint]";
		if (typeof candidate !== "object") {
			structurallyTruncated = true;
			return "[unsupported]";
		}
		if (seen.has(candidate)) {
			structurallyTruncated = true;
			return "[cycle]";
		}
		seen.add(candidate);
		if (Array.isArray(candidate)) {
			if (candidate.length > 64) structurallyTruncated = true;
			return candidate.slice(0, 64).map((item) => copy(item, depth + 1));
		}
		const prototype = Object.getPrototypeOf(candidate);
		if (prototype !== Object.prototype && prototype !== null) {
			structurallyTruncated = true;
			return "[unsupported]";
		}
		const descriptors = Object.getOwnPropertyDescriptors(candidate);
		const keys = Object.keys(descriptors).sort();
		if (keys.length > 64) structurallyTruncated = true;
		const result: Record<string, unknown> = Object.create(null);
		for (const key of keys.slice(0, 64)) {
			const descriptor = descriptors[key];
			if (!("value" in descriptor)) {
				structurallyTruncated = true;
				result[key] = "[accessor]";
			} else {
				result[key] = copy(descriptor.value, depth + 1);
			}
		}
		return result;
	};

	try {
		const encoded = JSON.stringify(copy(value, 0));
		if (typeof encoded !== "string") return { truncated: structurallyTruncated };
		const bounded = truncateUtf8(encoded, maximumBytes);
		return {
			text: bounded.text,
			truncated: structurallyTruncated || bounded.truncated,
			originalBytes: bounded.originalBytes,
		};
	} catch {
		return { text: "[unsupported]", truncated: true };
	}
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function unsupportedEntry(identity: string, reasonCode: string, timestamp: unknown): BridgeEntry {
	return {
		source_id: sourceID("unsupported", identity),
		source_revision: 1,
		timestamp: timestampSeconds(timestamp),
		state: "complete",
		kind: "unsupported",
		body: { type: "unsupported", reason_code: safeToken(reasonCode, "unsupported_item") },
		truncation: noTruncation(),
	};
}

function textEntry(
	identity: string,
	kind: BridgeEntry["kind"],
	content: unknown,
	timestamp: unknown,
	state: BridgeEntry["state"] = "complete",
): BridgeEntry | undefined {
	const preview = textPreview(content, MAX_TEXT_BYTES);
	if (preview.text === undefined || preview.text.length === 0) return undefined;
	return {
		source_id: sourceID("message", identity),
		source_revision: 1,
		timestamp: timestampSeconds(timestamp),
		state,
		kind,
		body: { type: "text", text: preview.text },
		truncation: truncation([preview]),
	};
}

function toolEntry(identity: string, tool: ToolState): BridgeEntry {
	const input = tool.input === undefined ? { truncated: false } : jsonPreview(tool.input, MAX_INPUT_PREVIEW_BYTES);
	const result = tool.result === undefined
		? { truncated: false }
		: isRecord(tool.result) && "content" in tool.result
			? textPreview(tool.result.content, MAX_RESULT_PREVIEW_BYTES)
			: textPreview(tool.result, MAX_RESULT_PREVIEW_BYTES);
	return {
		source_id: sourceID("tool", identity),
		source_revision: 1,
		timestamp: timestampSeconds(tool.timestamp),
		state: tool.complete ? (tool.isError ? "failed" : "complete") : "streaming",
		kind: "tool",
		body: {
			type: "tool",
			tool: {
				name: safeToken(tool.name, "unnamed_tool"),
				status: tool.complete ? (tool.isError ? "failed" : "complete") : "running",
				...(input.text === undefined ? {} : { input_preview: input.text }),
				...(result.text === undefined ? {} : { result_preview: result.text }),
			},
		},
		truncation: truncation([input, result]),
	};
}

function messageIdentity(message: Record<string, unknown>): string {
	return `${String(message.role ?? "unknown")}:${String(message.timestamp ?? "unknown")}`;
}

function mapMessage(message: unknown, stateOverride?: BridgeEntry["state"]): BridgeEntry[] {
	if (!isRecord(message) || typeof message.role !== "string") {
		return [unsupportedEntry("unknown-message", "unknown_message", Date.now())];
	}
	const identity = messageIdentity(message);
	if (message.role === "user") {
		const entry = textEntry(identity, "user_message", message.content, message.timestamp, stateOverride);
		return entry ? [entry] : [unsupportedEntry(identity, "non_text_message", message.timestamp)];
	}
	if (message.role === "assistant") {
		const entries: BridgeEntry[] = [];
		const text = textEntry(
			identity,
			"assistant_message",
			message.content,
			message.timestamp,
			stateOverride ?? (message.stopReason === "error" ? "failed" : "complete"),
		);
		if (text) entries.push(text);
		if (Array.isArray(message.content)) {
			for (const item of message.content) {
				if (isRecord(item) && item.type === "toolCall" && typeof item.id === "string") {
					entries.push(
						toolEntry(item.id, {
							name: typeof item.name === "string" ? item.name : "unnamed_tool",
							input: item.arguments,
							isError: false,
							timestamp: timestampSeconds(message.timestamp),
							complete: false,
						}),
					);
				} else if (isRecord(item) && item.type !== "text" && item.type !== "thinking") {
					entries.push(
						unsupportedEntry(`${identity}:${entries.length}`, "unknown_message_part", message.timestamp),
					);
				}
			}
		}
		if (entries.length === 0 && message.stopReason === "error") {
			const error = textEntry(identity, "error", "Pi reported an agent error.", message.timestamp, "failed");
			if (error) entries.push(error);
		}
		// Thinking-only messages are intentionally omitted; hidden reasoning is never requested.
		return entries;
	}
	if (message.role === "toolResult" && typeof message.toolCallId === "string") {
		return [
			toolEntry(message.toolCallId, {
				name: typeof message.toolName === "string" ? message.toolName : "unnamed_tool",
				result: message,
				isError: message.isError === true,
				timestamp: timestampSeconds(message.timestamp),
				complete: true,
			}),
		];
	}
	return [unsupportedEntry(identity, "unknown_message", message.timestamp)];
}

function entryTimestamp(entry: Record<string, unknown>): number {
	if (typeof entry.timestamp === "string") {
		const parsed = Date.parse(entry.timestamp);
		if (Number.isFinite(parsed)) return parsed;
	}
	return Date.now();
}

/** Maps only documented displayable session records. Non-display metadata is omitted. */
export function mapSessionBranch(entries: readonly SessionEntry[]): BridgeEntry[] {
	const mapped: BridgeEntry[] = [];
	const tools = new Map<string, BridgeEntry>();
	for (const raw of entries as readonly unknown[]) {
		if (!isRecord(raw) || typeof raw.type !== "string") {
			mapped.push(unsupportedEntry(`entry:${mapped.length}`, "unknown_session_entry", Date.now()));
			continue;
		}
		if (raw.type === "message") {
			for (const entry of mapMessage(raw.message)) {
				if (entry.kind === "tool") {
					const previous = tools.get(entry.source_id);
					if (previous?.body.type === "tool" && entry.body.type === "tool") {
						entry.body.tool.input_preview ??= previous.body.tool.input_preview;
						entry.timestamp = Math.min(previous.timestamp, entry.timestamp);
						if (previous.truncation.truncated && !entry.truncation.truncated) {
							entry.truncation = previous.truncation;
						}
					}
					tools.set(entry.source_id, entry);
				} else mapped.push(entry);
			}
			continue;
		}
		if (raw.type === "custom_message") {
			if (raw.display === true) {
				const entry = textEntry(
					`custom:${String(raw.id ?? mapped.length)}`,
					"system",
					raw.content,
					entryTimestamp(raw),
				);
				if (entry) mapped.push(entry);
			}
			continue;
		}
		if (raw.type === "compaction" || raw.type === "branch_summary") {
			const entry = textEntry(
				`${raw.type}:${String(raw.id ?? mapped.length)}`,
				"system",
				raw.summary,
				entryTimestamp(raw),
			);
			if (entry) mapped.push(entry);
			continue;
		}
		if (
			raw.type === "custom" ||
			raw.type === "session_info" ||
			raw.type === "model_change" ||
			raw.type === "thinking_level_change" ||
			raw.type === "label"
		) {
			continue;
		}
		mapped.push(
			unsupportedEntry(
				`${raw.type}:${String(raw.id ?? mapped.length)}`,
				"unknown_session_entry",
				entryTimestamp(raw),
			),
		);
	}

	// Tool-result records replace the matching call record rather than adding token/result rows.
	mapped.push(...tools.values());
	mapped.sort((left, right) => left.timestamp - right.timestamp || left.source_id.localeCompare(right.source_id));
	return boundSnapshot(mapped);
}

function entryContentBytes(entry: BridgeEntry): number {
	if (entry.body.type === "text") return utf8Bytes(entry.body.text);
	if (entry.body.type === "tool") {
		return (
			utf8Bytes(entry.body.tool.name) +
			utf8Bytes(entry.body.tool.status) +
			utf8Bytes(entry.body.tool.input_preview ?? "") +
			utf8Bytes(entry.body.tool.result_preview ?? "")
		);
	}
	return utf8Bytes(entry.body.reason_code);
}

function boundSnapshot(entries: BridgeEntry[]): BridgeEntry[] {
	let total = 0;
	const kept: BridgeEntry[] = [];
	for (let index = entries.length - 1; index >= 0 && kept.length < MAX_SNAPSHOT_ENTRIES; index -= 1) {
		const bytes = entryContentBytes(entries[index]);
		if (total + bytes > MAX_SNAPSHOT_BYTES) break;
		total += bytes;
		kept.push(entries[index]);
	}
	return kept.reverse();
}

function workspaceDisplay(cwd: string): string {
	const leaf = path.basename(cwd.trim());
	const candidate = leaf.length > 0 && leaf !== path.sep ? leaf : "Workspace";
	return truncateUtf8(candidate, 256).text || "Workspace";
}

function upstreamSessionIdentity(ctx: ExtensionContext): string {
	const id = ctx.sessionManager.getSessionId();
	return `pi-${createHash("sha256").update(id).digest("hex").slice(0, 40)}`;
}

function validOpaqueID(value: unknown): value is string {
	return typeof value === "string" && /^[0-9A-Za-z._-]{1,64}$/.test(value);
}

function strictKeys(value: WireObject, expected: readonly string[]): boolean {
	const actual = Object.keys(value).sort();
	const wanted = [...expected].sort();
	return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function decodeCommand(value: unknown): BridgeCommand | undefined {
	if (!isRecord(value) || value.v !== 1 || value.type !== "command") return undefined;
	if (!validOpaqueID(value.command_id)) return undefined;
	if (!(["prompt", "steer", "follow_up", "interrupt"] as unknown[]).includes(value.kind)) return undefined;
	const kind = value.kind as CommandKind;
	if (kind === "interrupt") {
		if (!strictKeys(value, ["v", "type", "command_id", "kind"])) return undefined;
		return value as unknown as BridgeCommand;
	}
	if (!strictKeys(value, ["v", "type", "command_id", "kind", "text"])) return undefined;
	if (typeof value.text !== "string" || value.text.length === 0 || utf8Bytes(value.text) > MAX_PROMPT_BYTES) {
		return undefined;
	}
	return value as unknown as BridgeCommand;
}

export function encodeBridgeFrame(value: unknown): Buffer {
	const body = Buffer.from(JSON.stringify(value), "utf8");
	if (body.length === 0 || body.length > MAX_FRAME_BYTES) throw new Error("bridge_frame_bound");
	const frame = Buffer.allocUnsafe(body.length + 4);
	frame.writeUInt32BE(body.length, 0);
	body.copy(frame, 4);
	return frame;
}

class FrameDecoder {
	private buffer = Buffer.alloc(0);

	push(chunk: Buffer): unknown[] {
		if (chunk.length === 0) return [];
		if (this.buffer.length + chunk.length > MAX_PENDING_BYTES) throw new Error("bridge_frame_bound");
		this.buffer = Buffer.concat([this.buffer, chunk]);
		const values: unknown[] = [];
		while (this.buffer.length >= 4) {
			const length = this.buffer.readUInt32BE(0);
			if (length === 0 || length > MAX_FRAME_BYTES) throw new Error("bridge_frame_bound");
			if (this.buffer.length < length + 4) break;
			const body = this.buffer.subarray(4, length + 4);
			this.buffer = this.buffer.subarray(length + 4);
			values.push(JSON.parse(STRICT_UTF8_DECODER.decode(body)));
		}
		return values;
	}
}

export class CiaoAgentBridge {
	private readonly pi: ExtensionAPI;
	private readonly socketPath: string;
	private socket?: net.Socket;
	private decoder = new FrameDecoder();
	private context?: ExtensionContext;
	private sessionIdentity?: string;
	private stopped = true;
	private registered = false;
	private connectionSerial = 0;
	private reconnectAttempt = 0;
	private reconnectTimer?: NodeJS.Timeout;
	private writeQueue: PendingWrite[] = [];
	private queuedBytes = 0;
	private writing = false;
	private revisions = new Map<string, number>();
	private coalescedEntries = new Map<string, BridgeEntry>();
	private coalesceTimers = new Map<string, NodeJS.Timeout>();
	private tools = new Map<string, ToolState>();
	private receipts = new Map<string, CachedReceipt>();
	private pendingApplications: PendingApplication[] = [];
	private lastCapabilities?: string;
	/// Pi's own idle flag is the turn boundary, and it already decides `interrupt`, so deriving
	/// both from it is what keeps the stop button and the working row from ever disagreeing.
	private lastTurnWorking?: boolean;
	private turnSequence = 0;
	private openRunID?: string;

	constructor(pi: ExtensionAPI, socketPath = defaultBridgeSocketPath()) {
		this.pi = pi;
		this.socketPath = socketPath;
	}

	start(ctx: ExtensionContext): void {
		this.stop(false);
		if (ctx.mode !== "tui") return;
		this.context = ctx;
		this.sessionIdentity = upstreamSessionIdentity(ctx);
		this.stopped = false;
		this.connect();
	}

	stop(processExited = false): void {
		this.stopped = true;
		this.context = undefined;
		this.sessionIdentity = undefined;
		this.registered = false;
		this.connectionSerial += 1;
		if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
		this.reconnectTimer = undefined;
		for (const timer of this.coalesceTimers.values()) clearTimeout(timer);
		this.coalesceTimers.clear();
		this.coalescedEntries.clear();
		this.pendingApplications = [];
		this.clearWrites();
		const socket = this.socket;
		this.socket = undefined;
		if (socket && !socket.destroyed) {
			try {
				socket.end(
					encodeBridgeFrame({
						v: BRIDGE_VERSION,
						type: "shutdown",
						reason: processExited ? "process_exit" : "session_replaced",
					}),
				);
			} catch {
				socket.destroy();
			}
		}
	}

	status(): "inactive" | "connecting" | "connected" {
		if (this.stopped) return "inactive";
		return this.registered ? "connected" : "connecting";
	}

	reconnect(): void {
		if (this.stopped) return;
		this.socket?.destroy();
		this.scheduleReconnect(true);
	}

	updateContext(ctx: ExtensionContext): void {
		if (ctx.mode !== "tui" || this.stopped) return;
		this.context = ctx;
		this.publishCapabilities();
		this.publishTurn();
	}

	reconcile(ctx: ExtensionContext): void {
		this.updateContext(ctx);
		this.sendSnapshot();
	}

	publishMessage(message: unknown, state?: BridgeEntry["state"]): void {
		if (
			isRecord(message) &&
			message.role === "toolResult" &&
			typeof message.toolCallId === "string"
		) {
			const tool = this.tools.get(message.toolCallId) ?? {
				name: typeof message.toolName === "string" ? message.toolName : "unnamed_tool",
				isError: message.isError === true,
				timestamp: timestampSeconds(message.timestamp),
				complete: true,
			};
			tool.result = message;
			tool.isError = message.isError === true;
			tool.complete = true;
			this.tools.set(message.toolCallId, tool);
			this.publishEntry(toolEntry(message.toolCallId, tool), false);
			return;
		}
		for (const entry of mapMessage(message, state)) this.publishEntry(entry, state === "streaming");
	}

	publishToolStart(toolCallId: string, toolName: string, args: unknown): void {
		const state: ToolState = {
			name: toolName,
			input: args,
			isError: false,
			timestamp: Date.now(),
			complete: false,
		};
		this.tools.set(toolCallId, state);
		this.publishEntry(toolEntry(toolCallId, state), false);
	}

	publishToolUpdate(toolCallId: string, toolName: string, args: unknown, result: unknown): void {
		const state = this.tools.get(toolCallId) ?? {
			name: toolName,
			input: args,
			isError: false,
			timestamp: Date.now(),
			complete: false,
		};
		state.result = result;
		this.tools.set(toolCallId, state);
		this.publishEntry(toolEntry(toolCallId, state), true);
	}

	publishToolEnd(toolCallId: string, toolName: string, result: unknown, isError: boolean): void {
		const state = this.tools.get(toolCallId) ?? {
			name: toolName,
			isError,
			timestamp: Date.now(),
			complete: true,
		};
		state.result = result;
		state.isError = isError;
		state.complete = true;
		this.tools.set(toolCallId, state);
		this.flushCoalesced(toolEntry(toolCallId, state).source_id);
		this.publishEntry(toolEntry(toolCallId, state), false);
	}

	observeInput(event: { text: string; source: string; streamingBehavior?: "steer" | "followUp" }): void {
		if (event.source !== "extension") return;
		const pending = this.pendingApplications.find(
			(candidate) =>
				!candidate.observed &&
				candidate.text === event.text &&
				candidate.expectedBehavior === event.streamingBehavior,
		);
		if (!pending) return;
		pending.observed = true;
		if (pending.accepted) this.applyPending(pending);
	}

	private connect(): void {
		if (this.stopped || this.socket || !this.context || !this.sessionIdentity) return;
		const serial = ++this.connectionSerial;
		const socket = net.createConnection({ path: this.socketPath });
		this.socket = socket;
		this.decoder = new FrameDecoder();
		socket.unref();
		socket.setTimeout(5_000, () => socket.destroy());
		socket.once("connect", () => {
			if (serial !== this.connectionSerial || this.stopped) return socket.destroy();
			socket.setTimeout(0);
			this.reconnectAttempt = 0;
			this.registered = false;
			this.lastCapabilities = undefined;
			this.enqueue({
				v: BRIDGE_VERSION,
				type: "register",
				adapter: "pi",
				adapter_version: VERSION,
				mode: "tui",
				session_id: this.sessionIdentity,
				process_nonce: processNonce(),
				process_id: process.pid,
				workspace_display: workspaceDisplay(this.context?.cwd ?? ""),
				commands: this.commands(),
			});
		});
		socket.on("data", (chunk: Buffer) => {
			if (serial !== this.connectionSerial) return;
			try {
				for (const value of this.decoder.push(chunk)) this.receive(value);
			} catch {
				socket.destroy();
			}
		});
		socket.once("error", () => {
			// Daemon absence and protocol failures are intentionally silent in the normal TUI.
		});
		socket.once("close", () => {
			if (serial !== this.connectionSerial) return;
			this.socket = undefined;
			this.registered = false;
			this.clearWrites();
			this.scheduleReconnect(false);
		});
	}

	private scheduleReconnect(immediate: boolean): void {
		if (this.stopped || this.reconnectTimer) return;
		const base = immediate ? 0 : Math.min(MAX_RECONNECT_DELAY_MS, 100 * 2 ** this.reconnectAttempt);
		this.reconnectAttempt = Math.min(this.reconnectAttempt + 1, 8);
		const jitter = base === 0 ? 0 : Math.floor(Math.random() * Math.max(1, base / 4));
		this.reconnectTimer = setTimeout(() => {
			this.reconnectTimer = undefined;
			this.connect();
		}, base + jitter);
		this.reconnectTimer.unref();
	}

	private receive(value: unknown): void {
		if (!isRecord(value) || value.v !== BRIDGE_VERSION || typeof value.type !== "string") {
			this.socket?.destroy();
			return;
		}
		if (value.type === "registered") {
			if (
				!strictKeys(value, ["v", "type", "session_id", "process_generation", "snapshot_epoch"]) ||
				!validOpaqueID(value.session_id) ||
				typeof value.process_generation !== "number" ||
				typeof value.snapshot_epoch !== "number"
			) {
				this.socket?.destroy();
				return;
			}
			this.registered = true;
			this.sendSnapshot();
			this.publishCapabilities();
			return;
		}
		if (value.type === "shutdown") {
			if (!strictKeys(value, ["v", "type", "reason_code"]) || typeof value.reason_code !== "string") {
				this.socket?.destroy();
				return;
			}
			this.socket?.destroy();
			return;
		}
		const command = decodeCommand(value);
		if (!command) {
			this.socket?.destroy();
			return;
		}
		this.handleCommand(command);
	}

	private sendSnapshot(): void {
		if (!this.registered || !this.context) return;
		this.revisions.clear();
		this.enqueue({ v: BRIDGE_VERSION, type: "snapshot_start" });
		for (const entry of mapSessionBranch(this.context.sessionManager.getBranch())) {
			const versioned = this.version(entry);
			this.enqueue({ v: BRIDGE_VERSION, type: "snapshot_entry", entry: versioned });
		}
		this.enqueue({ v: BRIDGE_VERSION, type: "snapshot_end" });
	}

	private publishEntry(entry: BridgeEntry, coalesce: boolean): void {
		if (!this.registered) return;
		if (!coalesce) {
			this.flushCoalesced(entry.source_id);
			this.enqueue({ v: BRIDGE_VERSION, type: "upsert_entry", entry: this.version(entry) });
			return;
		}
		this.coalescedEntries.set(entry.source_id, entry);
		if (this.coalesceTimers.has(entry.source_id)) return;
		const timer = setTimeout(() => {
			this.coalesceTimers.delete(entry.source_id);
			this.flushCoalesced(entry.source_id);
		}, LIVE_EMISSION_INTERVAL_MS);
		timer.unref();
		this.coalesceTimers.set(entry.source_id, timer);
	}

	private flushCoalesced(sourceId: string): void {
		const timer = this.coalesceTimers.get(sourceId);
		if (timer) clearTimeout(timer);
		this.coalesceTimers.delete(sourceId);
		const entry = this.coalescedEntries.get(sourceId);
		if (!entry || !this.registered) return;
		this.coalescedEntries.delete(sourceId);
		this.enqueue({ v: BRIDGE_VERSION, type: "upsert_entry", entry: this.version(entry) });
	}

	private version(entry: BridgeEntry): BridgeEntry {
		const revision = (this.revisions.get(entry.source_id) ?? 0) + 1;
		this.revisions.set(entry.source_id, revision);
		return { ...entry, source_revision: revision };
	}

	private commands(): BridgeCommands {
		if (!isPiMajorCompatible(VERSION)) {
			return { prompt: false, steer: false, follow_up: false, interrupt: false };
		}
		const surface = detectPiCommandSurface(this.pi, this.context);
		return {
			prompt: surface.send,
			steer: surface.deliverAs,
			follow_up: surface.deliverAs,
			interrupt: surface.abort && this.context?.isIdle() === false,
		};
	}

	private publishCapabilities(): void {
		if (!this.registered) return;
		const commands = this.commands();
		const encoded = JSON.stringify(commands);
		if (encoded === this.lastCapabilities) return;
		this.lastCapabilities = encoded;
		this.enqueue({ v: BRIDGE_VERSION, type: "capabilities", commands });
	}

	/// Every hook that refreshes the context runs this, so the turn tracks Pi's idle flag without
	/// a per-event wiring list to keep in step. Deduped like capabilities: only an actual edge is
	/// sent, so a chatty hook stream cannot churn host revisions.
	private publishTurn(): void {
		if (!this.registered) return;
		const ctx = this.context;
		if (typeof ctx?.isIdle !== "function") return;
		const working = ctx.isIdle() === false;
		if (working === this.lastTurnWorking) return;
		this.lastTurnWorking = working;
		if (working) {
			this.turnSequence += 1;
			this.openRunID = `run-${this.turnSequence}`;
			this.enqueue({
				v: BRIDGE_VERSION,
				type: "turn",
				state: "running",
				run_id: this.openRunID,
				activity: "thinking",
			});
			return;
		}
		this.enqueue({
			v: BRIDGE_VERSION,
			type: "turn",
			state: "completed",
			...(this.openRunID ? { run_id: this.openRunID } : {}),
		});
		this.openRunID = undefined;
	}

	private handleCommand(command: BridgeCommand): void {
		const cached = this.receipts.get(command.command_id);
		if (cached) {
			this.sendReceipt(command.command_id, cached);
			return;
		}
		const ctx = this.context;
		const surface = detectPiCommandSurface(this.pi, ctx);
		// Re-checked at execution, not trusted from the advertisement: capabilities are
		// published on change and the harness can lose a surface between the two.
		const usable =
			isPiMajorCompatible(VERSION) &&
			(command.kind === "interrupt" ? surface.abort : surface.send);
		if (!ctx || !usable) {
			this.rememberAndSend(command.command_id, { state: "rejected", reasonCode: "adapter_unavailable" });
			return;
		}
		if (command.kind === "interrupt") {
			if (ctx.isIdle()) {
				this.rememberAndSend(command.command_id, { state: "rejected", reasonCode: "agent_not_active" });
				return;
			}
			try {
				ctx.abort();
				this.rememberAndSend(command.command_id, { state: "accepted" });
				this.rememberAndSend(command.command_id, {
					state: "applied",
					evidence: "pi_abort_invoked",
				});
			} catch {
				this.rememberAndSend(command.command_id, { state: "rejected", reasonCode: "abort_rejected" });
			}
			return;
		}
		if (command.text === undefined) {
			this.rememberAndSend(command.command_id, { state: "rejected", reasonCode: "invalid_command" });
			return;
		}
		const idle = ctx.isIdle();
		if (command.kind === "prompt" && !idle) {
			this.rememberAndSend(command.command_id, { state: "rejected", reasonCode: "agent_busy" });
			return;
		}
		if (command.kind !== "prompt" && idle) {
			this.rememberAndSend(command.command_id, {
				state: "rejected",
				reasonCode: "agent_not_active",
			});
			return;
		}
		const expectedBehavior = command.kind === "steer" ? "steer" : command.kind === "follow_up" ? "followUp" : undefined;
		const pending: PendingApplication = {
			commandId: command.command_id,
			text: command.text,
			expectedBehavior,
			accepted: false,
			observed: false,
		};
		this.pendingApplications.push(pending);
		try {
			if (expectedBehavior) this.pi.sendUserMessage(command.text, { deliverAs: expectedBehavior });
			else this.pi.sendUserMessage(command.text);
			this.rememberAndSend(command.command_id, { state: "accepted" });
			pending.accepted = true;
			if (pending.observed) this.applyPending(pending);
		} catch {
			if (pending.observed) {
				pending.accepted = true;
				this.applyPending(pending);
			} else {
				this.pendingApplications = this.pendingApplications.filter((item) => item !== pending);
				this.rememberAndSend(command.command_id, {
					state: "rejected",
					reasonCode: "pi_rejected",
				});
			}
		}
	}

	private applyPending(pending: PendingApplication): void {
		this.pendingApplications = this.pendingApplications.filter((item) => item !== pending);
		this.rememberAndSend(pending.commandId, {
			state: "applied",
			evidence: "pi_input_event",
		});
	}

	private rememberAndSend(commandId: string, receipt: CachedReceipt): void {
		if (!this.receipts.has(commandId) && this.receipts.size >= MAX_RECEIPTS) {
			const oldest = this.receipts.keys().next().value;
			if (typeof oldest === "string") this.receipts.delete(oldest);
		}
		this.receipts.set(commandId, receipt);
		this.sendReceipt(commandId, receipt);
	}

	private sendReceipt(commandId: string, receipt: CachedReceipt): void {
		this.enqueue({
			v: BRIDGE_VERSION,
			type: "command_receipt",
			command_id: commandId,
			state: receipt.state,
			...(receipt.evidence ? { evidence: receipt.evidence } : {}),
			...(receipt.reasonCode ? { reason_code: receipt.reasonCode } : {}),
		});
	}

	private enqueue(value: unknown): void {
		const socket = this.socket;
		if (!socket || socket.destroyed) return;
		let bytes: Buffer;
		try {
			bytes = encodeBridgeFrame(value);
		} catch {
			socket.destroy();
			return;
		}
		if (this.queuedBytes + bytes.length > MAX_PENDING_BYTES) {
			socket.destroy();
			return;
		}
		this.writeQueue.push({ bytes });
		this.queuedBytes += bytes.length;
		this.drainWrites();
	}

	private drainWrites(): void {
		const socket = this.socket;
		if (this.writing || !socket || socket.destroyed) return;
		const next = this.writeQueue.shift();
		if (!next) return;
		this.writing = true;
		socket.write(next.bytes, (error?: Error | null) => {
			this.writing = false;
			this.queuedBytes = Math.max(0, this.queuedBytes - next.bytes.length);
			if (error) socket.destroy();
			else {
				next.onFlushed?.();
				this.drainWrites();
			}
		});
	}

	private clearWrites(): void {
		this.writeQueue = [];
		this.queuedBytes = 0;
		this.writing = false;
	}
}

export function registerCiaoAgentExtension(pi: ExtensionAPI, socketPath?: string): CiaoAgentBridge {
	const bridge = new CiaoAgentBridge(pi, socketPath);

	pi.on("session_start", (_event, ctx) => bridge.start(ctx));
	pi.on("session_shutdown", (event) => bridge.stop(event.reason === "quit"));
	pi.on("session_tree", (_event, ctx) => bridge.reconcile(ctx));
	pi.on("session_compact", (_event, ctx) => bridge.reconcile(ctx));
	pi.on("agent_start", (_event, ctx) => bridge.updateContext(ctx));
	pi.on("agent_end", (_event, ctx) => bridge.updateContext(ctx));
	pi.on("agent_settled", (_event, ctx) => bridge.updateContext(ctx));
	pi.on("message_update", (event, ctx) => {
		bridge.updateContext(ctx);
		bridge.publishMessage(event.message, "streaming");
	});
	pi.on("message_end", (event, ctx) => {
		bridge.updateContext(ctx);
		bridge.publishMessage(event.message);
	});
	pi.on("tool_execution_start", (event, ctx) => {
		bridge.updateContext(ctx);
		bridge.publishToolStart(event.toolCallId, event.toolName, event.args);
	});
	pi.on("tool_execution_update", (event, ctx) => {
		bridge.updateContext(ctx);
		bridge.publishToolUpdate(event.toolCallId, event.toolName, event.args, event.partialResult);
	});
	pi.on("tool_execution_end", (event, ctx) => {
		bridge.updateContext(ctx);
		bridge.publishToolEnd(event.toolCallId, event.toolName, event.result, event.isError);
	});
	pi.on("input", (event, ctx) => {
		bridge.updateContext(ctx);
		bridge.observeInput(event);
	});

	pi.registerCommand("ciao-agent", {
		description: "Show or reconnect the local Ciao Agent Session bridge",
		handler: async (args, ctx) => {
			const action = args.trim();
			if (action === "reconnect") {
				bridge.updateContext(ctx);
				bridge.reconnect();
				ctx.ui.notify("Ciao Agent Session bridge is reconnecting.", "info");
				return;
			}
			if (action.length !== 0 && action !== "status") {
				ctx.ui.notify("Usage: /ciao-agent [status|reconnect]", "warning");
				return;
			}
			const status = bridge.status();
			ctx.ui.notify(
				status === "connected"
					? "Ciao Agent Session bridge is connected."
					: status === "connecting"
						? "Ciao Agent Session bridge is waiting for the local daemon."
						: "Ciao Agent Session bridge is inactive outside normal TUI mode.",
				"info",
			);
		},
	});

	return bridge;
}

export default function ciaoAgentSessionExtension(pi: ExtensionAPI): void {
	registerCiaoAgentExtension(pi);
}
