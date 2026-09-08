import { expect, test } from "bun:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// The bootstrap installer's one security decision is the release base it will accept. Over
// plaintext the .sha256 sidecar travels the same channel as the archive it vouches for, so a
// transport attacker rewrites both and the checksum proves nothing. `ciao install` already
// refuses a non-https base (install.rs fetch_release_file, covered by its own unit test); these
// keep the shell path to the same rule, since it is the one a stranger runs first.
//
// Every case here exits at the guard, before any network call, so the suite stays offline.
const SCRIPT = new URL("./install.sh", import.meta.url).pathname;

function install(env) {
	const child = Bun.spawnSync(["sh", SCRIPT], {
		env: { PATH: process.env.PATH, ...env },
		stdout: "pipe",
		stderr: "pipe",
	});
	return {
		code: child.exitCode,
		out: child.stdout.toString(),
		err: child.stderr.toString(),
	};
}

test.each([
	["http://example.invalid/dist", "plaintext"],
	["file:///etc", "a local path"],
	["ftp://example.invalid", "another scheme entirely"],
	["ciaooo.app/dist", "a bare host with no scheme"],
])("a release base over %s is refused (%s)", (base) => {
	const { code, err } = install({ CIAO_BASE_URL: base });

	expect(code).toBe(1);
	expect(err).toContain("refusing a non-https release base");
	// The refusal has to say how to proceed deliberately, or the next person edits the script.
	expect(err).toContain("CIAO_ALLOW_INSECURE_BASE=1");
});

test("the opt-out warns loudly and then proceeds", () => {
	// Port 9 is discard: the guard is passed, and the run dies at the download instead. That
	// distinction is the assertion — reaching curl proves the base was accepted.
	const { code, err } = install({
		CIAO_BASE_URL: "http://127.0.0.1:9/dist",
		CIAO_ALLOW_INSECURE_BASE: "1",
	});

	expect(err).toContain("WARNING");
	expect(err).toContain("nothing is authenticated");
	expect(err).not.toContain("refusing");
	expect(err).toContain("could not read version");
	expect(code).not.toBe(0);
});

test("an https base is not diverted by the guard", () => {
	// Same discard port, so this also stops at the download rather than installing anything.
	const { code, err } = install({ CIAO_BASE_URL: "https://127.0.0.1:9/dist" });

	expect(err).not.toContain("refusing");
	expect(err).not.toContain("WARNING");
	expect(err).toContain("could not read version");
	expect(code).not.toBe(0);
});

// The existing-install guard. Dropping a new binary beside an already-running daemon leaves the
// CLI and the daemon at different versions with nothing saying so, and the first thing that
// breaks is pairing — which is version-coupled, so the phone reports an error that names nothing
// about versions. Reported 2026-08-01 from a 0.1.7 host that had just run this script.
//
// These serve a real manifest from a local port so the script gets past its version lookup, and
// assert on what it does with a `ciao` it finds already there.
function withManifest(version, run) {
	const server = Bun.serve({
		port: 0,
		fetch: () =>
			new Response(
				JSON.stringify({ v: 1, artifacts: [{ version, target: "x", file: "f", sha256: "d" }] }),
			),
	});
	try {
		return run(`http://127.0.0.1:${server.port}/dist`);
	} finally {
		server.stop(true);
	}
}

function fakeHome(version) {
	const home = fs.mkdtempSync(path.join(os.tmpdir(), "ciao-install-"));
	const bin = path.join(home, ".local", "bin");
	fs.mkdirSync(bin, { recursive: true });
	const binary = path.join(bin, "ciao");
	fs.writeFileSync(binary, `#!/bin/sh\necho "ciao ${version}"\n`, { mode: 0o755 });
	return { home, binary };
}

test("an install already at the offered version is left alone", () => {
	const { home, binary } = fakeHome("0.9.9");
	const before = fs.readFileSync(binary, "utf8");
	const { code, out } = withManifest("0.9.9", (base) =>
		install({ CIAO_BASE_URL: base, CIAO_ALLOW_INSECURE_BASE: "1", HOME: home }),
	);

	expect(code).toBe(0);
	expect(out).toContain("already installed");
	// Nothing downloaded and nothing swapped: the same file is still there.
	expect(fs.readFileSync(binary, "utf8")).toBe(before);
});

// The fresh-install tail. The app's Pair screen sends a newcomer here with the phone already
// in hand, so a completed install offers to end at the pairing QR itself instead of naming one
// more command to type. These run the whole script against a served fake dist whose "binary"
// is a stub that echoes its argv — reaching the stub proves the handover happened.
function withDist(version, run) {
	// Must derive the same target install.sh derives from uname on the machine running the
	// tests: aarch64 Mac for a dev checkout, x86_64 Linux in CI.
	const target =
		process.platform === "darwin" ? "aarch64-apple-darwin" : "x86_64-unknown-linux-gnu";
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ciao-dist-"));
	fs.writeFileSync(path.join(dir, "ciao"), '#!/bin/sh\necho "stub-ciao $*"\n', { mode: 0o755 });
	const file = `ciao-${version}-${target}.tar`;
	Bun.spawnSync(["tar", "-cf", path.join(dir, file), "-C", dir, "ciao"]);
	const bytes = fs.readFileSync(path.join(dir, file));
	const hasher = new Bun.CryptoHasher("sha256");
	hasher.update(bytes);
	const sha = hasher.digest("hex");
	const server = Bun.serve({
		port: 0,
		fetch: (req) => {
			const p = new URL(req.url).pathname;
			if (p.endsWith("/release.json"))
				return new Response(JSON.stringify({ v: 1, artifacts: [{ version, target, file, sha256: sha }] }));
			if (p.endsWith(`/${file}`)) return new Response(bytes);
			if (p.endsWith(`/${file}.sha256`)) return new Response(`${sha}  ${file}\n`);
			return new Response("not found", { status: 404 });
		},
	});
	try {
		return run(`http://127.0.0.1:${server.port}/dist`);
	} finally {
		server.stop(true);
		fs.rmSync(dir, { recursive: true, force: true });
	}
}

function freshHome() {
	return fs.mkdtempSync(path.join(os.tmpdir(), "ciao-home-"));
}

// python3's pty module gives the run a real terminal, so `[ -t 1 ]` and `/dev/tty` are live
// the way they are for a person who pasted the curl line. Keystrokes arrive via the pty.
// (script(1) would be the obvious tool, but the macOS one insists its own stdin is a tty.)
function installPTY(env, keys) {
	const child = Bun.spawnSync(
		["python3", "-c", "import pty,sys; pty.spawn(sys.argv[1:])", "sh", SCRIPT],
		{
			env: { PATH: process.env.PATH, ...env },
			stdin: Buffer.from(keys),
			stdout: "pipe",
			stderr: "pipe",
		},
	);
	return { out: child.stdout.toString() + child.stderr.toString() };
}

test("a fresh non-interactive install lands the binary and names `ciao pair` as the next step", () => {
	const home = freshHome();
	const { code, out } = withDist("0.9.9", (base) =>
		install({
			CIAO_BASE_URL: base,
			CIAO_ALLOW_INSECURE_BASE: "1",
			HOME: home,
			CIAO_NONINTERACTIVE: "1",
		}),
	);

	expect(code).toBe(0);
	expect(out).toContain("Installed ciao 0.9.9");
	// One first command everywhere: the app's Pair screen, this line, and the README all
	// name `ciao pair`. Naming bare `ciao` here was the third divergent answer.
	expect(out).toContain("ciao pair");
	expect(out).not.toContain("pairing QR now?");
	const installed = Bun.spawnSync([path.join(home, ".local", "bin", "ciao")]);
	expect(installed.stdout.toString()).toContain("stub-ciao");
});

test("a piped fresh install never prompts", () => {
	// No CIAO_NONINTERACTIVE: piped stdout alone must keep provisioning scripts off the
	// prompt, because `read < /dev/tty` would hang or steal input where a terminal exists.
	const home = freshHome();
	const { code, out } = withDist("0.9.9", (base) =>
		install({ CIAO_BASE_URL: base, CIAO_ALLOW_INSECURE_BASE: "1", HOME: home }),
	);

	expect(code).toBe(0);
	expect(out).not.toContain("pairing QR now?");
	expect(out).not.toContain("stub-ciao");
});

test("a fresh install at a terminal offers pairing and Enter hands over to the binary", () => {
	const home = freshHome();
	const { out } = withDist("0.9.9", (base) =>
		installPTY({ CIAO_BASE_URL: base, CIAO_ALLOW_INSECURE_BASE: "1", HOME: home }, "\n"),
	);

	expect(out).toContain("pairing QR now?");
	// The handover execs `ciao setup --yes`, not `ciao pair`: on a host with no paired
	// devices setup already ends at the pairing QR, and every released binary understands
	// it — `pair` only learned to run setup itself later, so exec'ing it would couple this
	// script's deploy to a host release.
	expect(out).toContain("stub-ciao setup --yes");
});

test("declining the pairing offer still names the next command", () => {
	const home = freshHome();
	const { out } = withDist("0.9.9", (base) =>
		installPTY({ CIAO_BASE_URL: base, CIAO_ALLOW_INSECURE_BASE: "1", HOME: home }, "n\n"),
	);

	expect(out).not.toContain("stub-ciao");
	expect(out).toContain("ciao pair");
});

test("an older install is never overwritten unattended", () => {
	const { home, binary } = fakeHome("0.1.7");
	const before = fs.readFileSync(binary, "utf8");
	const { code, out, err } = withManifest("0.1.14", (base) =>
		install({
			CIAO_BASE_URL: base,
			CIAO_ALLOW_INSECURE_BASE: "1",
			HOME: home,
			CIAO_NONINTERACTIVE: "1",
		}),
	);

	expect(code).toBe(1);
	expect(out).toContain("0.1.7 is installed; 0.1.14 is available");
	// It must name the command that does the upgrade correctly, or the reader is stuck.
	expect(err).toContain("ciao update");
	// The whole point: the old binary is still the old binary, so the running daemon and the
	// CLI beside it cannot disagree about their version.
	expect(fs.readFileSync(binary, "utf8")).toBe(before);
});
