#!/usr/bin/env python3
"""Exercise real Codex TUIs and Ciao against an owned, local Responses fixture.

No account, service installation, production configuration or real model is used. The
only trust approval is the official /hooks UI in the disposable vendor home, after the
installed hook commands have been checked. Every process and tmux session is owned by
this invocation. Prerequisite: a CURRENT `cargo build --locked -p ciao-host -j4`
(in host/), including matching libciao_host.rlib and deps. Intervening Cargo tests can
leave stale helper inputs (E0460); rebuild before running, never during a rehearsal.

A passing rehearsal is not qualification: paired terminal.open route-token use is
not exercised here. Extended receipts require idle-new-TUI recovery but retain the
separate typed route-use and visual-destination qualification gaps.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
from dataclasses import dataclass
import hashlib
import http.server
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import uuid


ANSWER = "CiaoLocalRehearsal"
MAX_LOG_BYTES = 8 * 1024 * 1024
# Baseline: three turns. Extended: two new side turns, NO post-restart repair
# turns. Retain the request ceiling, with one title request per turn plus catalog GETs
# across four TUI incarnations and the shared backend. Focus checks spend no turns.
MAX_RESPONSE_REQUESTS = 16
MAX_HTTP_REQUESTS = 24
ANSI = re.compile(r"\x1b\[[0-9;]*m")
# Extended local-only rehearsal: inherited by vendor hooks/history children too.
# Loopback IP and Unix IPC remain available; public Iroh/model/update traffic does not.
LOCAL_NETWORK_POLICY = """(version 1)
(allow default)
(deny network*)
(allow network-bind (local ip "*:*"))
(allow network-inbound (local ip "localhost:*"))
(allow network-outbound (remote ip "localhost:*"))
(allow network-bind (local unix-socket))
(allow network-outbound (remote unix-socket))
"""


class Refused(RuntimeError):
    """A fixed category, with no terminal, request or credential content."""


@dataclass(frozen=True)
class Selection:
    thread: str
    generation: int


def snapshot_generation(snapshot: dict | None, server: dict) -> int | None:
    if not isinstance(snapshot, dict) or type(snapshot.get("v")) is not int or snapshot["v"] != 1:
        return None
    generation = snapshot.get("generation")
    attached = snapshot.get("attached_thread_ids")
    if (type(generation) is not int or generation <= 0
            or not isinstance(attached, list) or len(attached) > 64
            or any(not isinstance(item, str) or not re.fullmatch(
                r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", item) for item in attached)
            or len(set(attached)) != len(attached)
            or "displayed_thread_id" not in snapshot
            or snapshot.get("connection") != {"kind": "local_daemon", "state": "connected", "server": server}):
        return None
    return generation


def live_selection(snapshot: dict | None, server: dict, expected: str | None = None,
                   after: Selection | None = None) -> Selection | None:
    """A pending/restoring/replay selection is never evidence of a live route."""
    generation = snapshot_generation(snapshot, server)
    if generation is None:
        return None
    thread = snapshot["displayed_thread_id"]
    if (thread not in snapshot["attached_thread_ids"]
            or (expected is not None and thread != expected)
            or (after is not None and generation <= after.generation)):
        return None
    return Selection(thread, generation)


def cleared_selection(snapshot: dict | None, server: dict) -> int | None:
    generation = snapshot_generation(snapshot, server)
    return generation if generation is not None and snapshot["displayed_thread_id"] is None else None


def mapped_session(document: dict, thread: str) -> str | None:
    """Join the exact vendor UUID, not whichever mapping happened to appear."""
    value = thread.encode()
    identity = hashlib.sha256(b"ciao-agent-identity-v1\0" + bytes.fromhex(document["key"])
                              + len(value).to_bytes(8, "big") + value).hexdigest()
    matches = [row["session_id"] for row in document["mappings"]
               if row["upstream_digest"] == identity and row["adapter_family"] == "Codex"]
    if len(matches) > 1:
        raise Refused("ambiguous_exact_thread_mapping")
    return matches[0] if matches else None


def exact_route_pairs(log: str) -> set[tuple[str, int]]:
    return route_pairs(log, "exact_live")


def route_pairs(log: str, continuity: str) -> set[tuple[str, int]]:
    pairs = set()
    for line in log.splitlines():
        if "agent route resolve" not in line or f'route="{continuity}"' not in line:
            continue
        session = re.search(r'\bsession=(?:"([^" ]+)"|([^ ]+))', line)
        pid = re.search(r"\bpid=(\d+)(?: |$)", line)
        if session and pid:
            pairs.add((session.group(1) or session.group(2), int(pid.group(1))))
    return pairs


def completed_recovery(log: str, expected: set[tuple[str, int]]) -> bool:
    """Enumeration is not a route barrier; the caller bounds pending route commits."""
    counts = [int(match.group(1)) for line in log.splitlines()
              if "re-adopted attached agent sessions after startup" in line
              for match in [re.search(r"\breadopted=(\d+)\b", line)] if match]
    if not counts:
        return False
    actual = exact_route_pairs(log)
    failed = set().union(*(route_pairs(log, state) for state in ("none", "workspace_only", "unavailable")))
    shared = sum(1 for line in log.splitlines()
                 if "Codex shared observation recovered" in line and "shared_recovered=1" in line)
    if (len(counts) != 1 or counts[0] + shared > len(expected)
            or len(actual) > counts[0] + shared or actual - expected or failed):
        raise Refused("observer_recovery_selected_thread_set_mismatch")
    # A missing commit is pending, never success. cold_checkpoint's existing predicate
    # deadline refuses a permanently missing route; no fixed delay or extra retry lane.
    return counts[0] + shared == len(expected) and actual == expected


def chooser_labels(screen: str) -> list[str]:
    """Only numbered fixture names on actual chooser rows, not transcript mentions."""
    return re.findall(r"[› ]\s+○\s+(CiaoSide[12])\b", screen)


def digest(path: Path) -> str | None:
    if not path.is_file():
        return None
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


class LocalResponses:
    def __init__(self) -> None:
        fixture = self
        self.requests = 0
        self.http_requests = 0
        self.over_budget = False
        self.lock = threading.Lock()

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args: object) -> None:
                pass

            def setup(self) -> None:
                super().setup()
                self.connection.settimeout(3)

            def admitted(self, response: bool = False) -> bool:
                with fixture.lock:
                    fixture.http_requests += 1
                    if response:
                        fixture.requests += 1
                        self.response_number = fixture.requests
                    fixture.over_budget |= (fixture.http_requests > MAX_HTTP_REQUESTS
                                            or fixture.requests > MAX_RESPONSE_REQUESTS)
                    allowed = not fixture.over_budget
                if not allowed:
                    self.send_error(429)
                return allowed

            def do_GET(self) -> None:
                if not self.admitted():
                    return
                if self.path.rstrip("/").endswith("/models"):
                    body = json.dumps({"object": "list", "data": [{"id": "gpt-5.4", "object": "model"}]}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_error(404)

            def do_POST(self) -> None:
                if not self.admitted(response=True):
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    self.send_error(400)
                    return
                if not self.path.rstrip("/").endswith("/responses") or not 0 < length <= 1024 * 1024:
                    self.send_error(400)
                    return
                # Consume the bounded fictional request; never retain or print its contents.
                self.rfile.read(length)
                number = self.response_number
                response_id = f"ciao-fixture-{number}"
                events = [
                    {"type": "response.created", "response": {"id": response_id}},
                    {"type": "response.output_item.done", "item": {
                        "type": "message", "role": "assistant", "id": f"message-{number}",
                        "content": [{"type": "output_text", "text": f"{ANSWER}-{number}"}],
                    }},
                    {"type": "response.completed", "response": {
                        "id": response_id,
                        "usage": {"input_tokens": 0, "input_tokens_details": None,
                                  "output_tokens": 0, "output_tokens_details": None, "total_tokens": 0},
                    }},
                ]
                body = "".join(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n" for event in events).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                    self.wfile.write(body)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}/v1"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def vendor_config(url: str, workspace: bool) -> str:
    # Upstream tui/src/daemon_startup.rs::config_exclusion permits boolean feature
    # overrides and tui.fullscreen_transcript, NOT keymap or alternate_screen -c.
    # Load owned preferences before starting the shared backend, or the TUI silently
    # falls back to embedded. The daemon also compares allowed feature overrides: it
    # must load tui_workspace before launch, not merely accept the TUI's -c syntax.
    preferences = '''alternate_screen = "always"
[tui.keymap.global]
focus_sidebar_tabs = "f6"
focus_main_composer = "f7"
focus_sidebar_content = "f8"
hide_pane = "f9"
''' if workspace else ""
    return f'''model = "gpt-5.4"
model_provider = "ciao_fixture"
approval_policy = "never"
sandbox_mode = "read-only"
cli_auth_credentials_store = "file"
check_for_update_on_startup = false
[analytics]
enabled = false
[features]
hooks = true
tui_workspace = {str(workspace).lower()}
daemon_auto_start = false
apps = false
remote_plugin = false
[tui]
pet = "disabled"
{preferences}[model_providers.ciao_fixture]
name = "Ciao local fixture"
base_url = "{url}"
wire_api = "responses"
requires_openai_auth = false
supports_websockets = false
request_max_retries = 0
stream_max_retries = 0
'''


def tui_options(standalone: bool, workspace: bool, resume: str | None) -> list[str]:
    options = ["--no-daemon"] if standalone else []
    if workspace:
        options.extend(["-c", "features.tui_workspace=true", "-c", "tui.fullscreen_transcript=true"])
    options.extend(["resume", resume] if resume else [f"Reply only {ANSWER}. Do not use tools."])
    return options


class Rehearsal:
    def __init__(self, args: argparse.Namespace, root: Path) -> None:
        self.args, self.root = args, root
        self.deadline = time.monotonic() + args.timeout
        self.owner_home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
        self.home, self.codex_home = root / "home", root / "codex"
        self.project = root / "project"
        self.bin = self.home / ".local/bin"
        for path in (self.home, self.codex_home, self.project, self.bin):
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.home.resolve() == self.owner_home or not self.home.resolve().is_relative_to(root.resolve()):
            raise Refused("home_isolation_failed")
        self.owner_files = [self.owner_home / ".codex/config.toml", self.owner_home / ".codex/hooks.json",
                            self.owner_home / ".local/bin/ciao"]
        self.owner_hashes = {path: digest(path) for path in self.owner_files}
        self.processes: list[subprocess.Popen[bytes]] = []
        self.sessions: list[str] = []
        self.panes: dict[str, str] = {}
        self.outputs: list[Path] = []
        self.owned_sockets: list[tuple[Path, int, int]] = []
        self.rows: list[dict[str, object]] = []
        self.side_evidence: list[dict[str, object]] = []
        self.side_lifecycle: dict[str, object] = {}
        self.network_prefix: list[str] = []
        if args.persisted_side_chats:
            if sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").is_file():
                raise Refused("extended_rehearsal_requires_macos_network_fence")
            self.network_prefix = ["/usr/bin/sandbox-exec", "-p", LOCAL_NETWORK_POLICY]
        self.daemon_label = "ciao-daemon"
        self.tui_identities: dict[int, str] = {}
        self.tmux = shutil.which("tmux")
        self.rustc = shutil.which("rustc")
        if not self.tmux or not self.rustc:
            raise Refused("tmux_or_rustc_missing")
        # Resolve a rustup/mise shim before isolating HOME; querying the sysroot is read-only.
        compiler = subprocess.run([self.rustc, "--print", "sysroot"], capture_output=True, timeout=10)
        native_rustc = Path(compiler.stdout.decode().strip()) / "bin/rustc"
        if compiler.returncode or not native_rustc.is_file():
            raise Refused("native_rustc_unavailable")
        self.rustc = str(native_rustc)
        self.env = {
            "HOME": str(self.home), "CODEX_HOME": str(self.codex_home),
            "PATH": f"{self.bin}:/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin",
            "TERM": "xterm-256color", "LANG": "en_US.UTF-8", "TMPDIR": "/tmp",
            "XDG_CONFIG_HOME": str(self.home / ".config"),
            "XDG_STATE_HOME": str(self.home / ".state"),
            "XDG_RUNTIME_DIR": str(self.home / ".run"),
            "OPENAI_API_KEY": "ciao-owned-local-fixture",
            "HTTP_PROXY": "http://127.0.0.1:9", "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9", "NO_PROXY": "127.0.0.1,localhost",
            "RUST_LOG": "ciao_host=debug",
        }
        self.ciao, self.codex = self.bin / "ciao", self.bin / "codex"
        self.source_hashes = {}
        for source, destination in ((args.ciao_binary, self.ciao), (args.codex_binary, self.codex)):
            before = digest(source)
            if before is None:
                raise Refused("candidate_binary_missing")
            shutil.copyfile(source, destination)
            destination.chmod(0o700)
            if digest(destination) != before or digest(source) != before:
                raise Refused("candidate_changed_during_copy")
            self.source_hashes[destination.name] = before
            if sys.platform == "darwin":
                self.run(["/usr/bin/codesign", "--force", "--sign", "-", str(destination)], "candidate_sign", 20)
        self.mock = LocalResponses()
        self.tuis: list[tuple[int, str]] = []

    def remaining(self, limit: float) -> float:
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise Refused("rehearsal_deadline")
        return min(left, limit)

    def run(self, argv: list[str], label: str, timeout_seconds: float = 10) -> bytes:
        if argv[0] in (str(self.ciao), str(self.codex)):
            argv = [*self.network_prefix, *argv]
        try:
            result = subprocess.run(argv, env=self.env, cwd=self.project,
                                    stdin=subprocess.DEVNULL, capture_output=True,
                                    timeout=self.remaining(timeout_seconds), check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise Refused(label + "_unavailable") from None
        if result.returncode or len(result.stdout) > 65536 or len(result.stderr) > 65536:
            raise Refused(label + "_failed")
        return result.stdout

    def spawn(self, argv: list[str], label: str, env: dict[str, str] | None = None) -> subprocess.Popen[bytes]:
        output = self.root / (label + ".log")
        handle = output.open("wb")
        output.chmod(0o600)
        self.outputs.append(output)
        # macOS refuses to exec setuid /bin/ps inside Seatbelt, even with allow-default.
        # The observer needs ps for kernel ancestry. Explicitly authorized normal observer
        # transport also permits Iroh relays; vendor backends/TUIs remain loopback-fenced.
        observer_network = (self.args.allow_observer_network
                            and argv == [str(self.ciao), "daemon"])
        prefix = [] if observer_network else self.network_prefix
        child_env = self.env if env is None else env
        if observer_network:
            child_env = {key: value for key, value in child_env.items()
                         if key not in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")}
        try:
            child = subprocess.Popen([*prefix, *argv], env=child_env, cwd=self.project,
                                     stdin=subprocess.DEVNULL, stdout=handle, stderr=subprocess.STDOUT,
                                     start_new_session=True)
        finally:
            handle.close()
        self.processes.append(child)
        return child

    def wait(self, label: str, predicate, seconds: float = 30):
        end = time.monotonic() + self.remaining(seconds)
        while time.monotonic() < end:
            if any(path.stat().st_size > MAX_LOG_BYTES for path in self.outputs):
                raise Refused("owned_log_exceeded_bound")
            result = predicate()
            if result:
                return result
            time.sleep(0.1)
        raise Refused(label + "_timeout")

    def initialize(self) -> None:
        self.run(["/usr/bin/git", "init", "-q"], "workspace_init")
        (self.project / "README.md").write_text("Fictional Ciao terminal compatibility fixture.\n")
        lib = self.args.ciao_binary.parent / "libciao_host.rlib"
        dependencies = self.args.ciao_binary.parent / "deps"
        if not lib.is_file() or not dependencies.is_dir():
            raise Refused("build_ciao_host_before_rehearsal")
        source, helper = self.root / "identity.rs", self.root / "identity"
        source.write_text('''fn main() {
    let paths = ciao_host::storage::CiaoPaths::discover().unwrap();
    let root = std::path::PathBuf::from(std::env::args_os().nth(1).unwrap());
    assert!(paths.home.starts_with(&root));
    ciao_host::identity::create_or_load_identity(&paths).unwrap();
    println!("{}", paths.agent_metadata_file.display());
    println!("{}", paths.logs_dir.display());
    println!("{}", paths.socket_file.display());
}\n''')
        self.run([self.rustc, "--edition=2024", "--crate-name", "ciao_rehearsal_identity", str(source),
                  "--extern", f"ciao_host={lib}", "-L", f"dependency={dependencies}", "-o", str(helper)],
                 "identity_helper_build", 60)
        paths = self.run([str(helper), str(self.root)], "identity_init").decode().splitlines()
        if len(paths) != 3:
            raise Refused("identity_helper_protocol")
        self.metadata, self.logs, self.ipc = map(Path, paths)
        if not all(path.resolve().is_relative_to(self.root.resolve()) for path in (self.metadata, self.logs, self.ipc)):
            raise Refused("ciao_paths_not_isolated")
        self.trace = self.logs / "codex-hook.trace.log"
        self.trace.touch(mode=0o600)
        (self.codex_home / "config.toml").write_text(
            vendor_config(self.mock.url, self.args.persisted_side_chats))
        # Cold developer binaries have measured >24s installation; only this operation
        # gets 60s. run() still clamps it to the overall (at most 600s) deadline.
        self.run([str(self.ciao), "agent", "install", "codex"], "hook_install", 60)
        hooks = self.codex_home / "hooks.json"
        document = json.loads(hooks.read_text())
        commands = [hook["command"] for groups in document["hooks"].values()
                    for group in groups for hook in group["hooks"]]
        if len(commands) != 7 or any(command != f"'{self.ciao}' __codex-hook" for command in commands):
            raise Refused("owned_hooks_not_exactly_reviewed_ciao_commands")
        self.hooks_hash = digest(hooks)
        if "trusted_hash" in (self.codex_home / "config.toml").read_text():
            raise Refused("unexpected_preexisting_hook_trust")
        self.daemon_env = {key: value for key, value in self.env.items() if key != "CODEX_HOME"}
        self.daemon = self.spawn([str(self.ciao), "daemon"], "ciao-daemon", self.daemon_env)
        self.wait("ciao_daemon", lambda: self.ipc.is_socket() and self.daemon.poll() is None)
        # A foreground owned app-server supplies the normal canonical local daemon socket.
        # Auto-install/updater behavior is deliberately outside this binary-only rehearsal.
        endpoint = self.codex_home / "app-server-control/app-server-control.sock"
        self.backend = self.spawn([str(self.codex), "app-server", "--listen", "unix://" + str(endpoint)], "codex-backend")
        self.wait("shared_backend", lambda: endpoint.exists() and self.backend.poll() is None)
        physical = endpoint.resolve(strict=True)
        metadata = physical.stat()
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid():
            raise Refused("owned_backend_endpoint_not_a_private_socket")
        self.owned_sockets.append((physical, metadata.st_dev, metadata.st_ino))
        self.server_identity = {"pid": self.backend.pid, "identity": self.kernel_identity(self.backend.pid)}

    def tmux_command(self, *args: str) -> bytes:
        # Use the real account socket so the candidate's unchanged provider can resolve it.
        # No global options, focus changes, server shutdown or existing session are touched.
        return self.run([self.tmux, *args], "owned_tmux")

    def pane_value(self, pane: str, format_string: str) -> str:
        return self.tmux_command("display-message", "-p", "-t", pane, format_string).decode().strip()

    def keys(self, session: str, pane: str, *keys: str, literal: bool = False) -> None:
        if (session not in self.sessions or not re.fullmatch(r"%[0-9]+", pane)
                or self.panes.get(session) != pane
                or self.pane_value(pane, "#{session_name}") != session):
            raise Refused("input_target_not_owned")
        self.tmux_command("send-keys", "-t", pane, *( ["-l"] if literal else []), *keys)

    def screen(self, pane: str) -> str:
        return self.tmux_command("capture-pane", "-p", "-t", pane).decode(errors="replace")

    def start_tui(self, standalone: bool, *, workspace: bool = False,
                  resume: str | None = None) -> tuple[str, str, int]:
        session = "ciao-rehearse-" + uuid.uuid4().hex[:12]
        env_args = [f"{key}={value}" for key, value in self.env.items()]
        options = tui_options(standalone, workspace, resume)
        # Register the exact random target before spawning so a timeout also cleans it up.
        self.sessions.append(session)
        # Obtain the pane from creation itself. '=session' is not an exact target-pane;
        # display-message can return empty, silently making later -t '' use another TUI.
        pane = self.tmux_command("new-session", "-d", "-E", "-P", "-F", "#{pane_id}",
                                 "-s", session, "-x", "160", "-y", "50", "-c", str(self.project),
                                 # Preserve only the markers generated by this new tmux child.
                                 # Removing them disables Codex's lost-resize recovery monitor.
                                 "/bin/sh", "-c",
                                 'exec /usr/bin/env -i "TMUX=${TMUX:?}" "TMUX_PANE=${TMUX_PANE:?}" "$@"',
                                 "ciao-owned-tmux", *env_args, *self.network_prefix,
                                 str(self.codex), *options).decode().strip()
        if not re.fullmatch(r"%[0-9]+", pane):
            raise Refused("created_pane_identity_invalid")
        self.panes[session] = pane
        pid = int(self.pane_value(pane, "#{pane_pid}"))
        start = self.run(["/bin/ps", "-p", str(pid), "-o", "lstart="], "owned_tui_identity").decode().strip()
        self.tuis.append((pid, start))
        self.tui_identities[pid] = self.kernel_identity(pid)
        trusted = False
        hooks_reviewed = False

        def ready():
            nonlocal trusted, hooks_reviewed
            text = self.screen(pane)
            if "Hooks need review" in text and not hooks_reviewed:
                if "7 hooks are new or changed" not in text or digest(self.codex_home / "hooks.json") != self.hooks_hash:
                    raise Refused("unexpected_startup_hook_review")
                # Select the official "Trust all and continue" item, then explicitly confirm.
                # Only the seven exact candidate Ciao commands were admitted above.
                self.keys(session, pane, "Down", "Enter")
                hooks_reviewed = True
                return False
            if "Trust this folder?" in text and not trusted:
                if str(self.project) not in text:
                    raise Refused("unexpected_workspace_trust_target")
                self.keys(session, pane, "1", "Enter")
                trusted = True
                return False
            status = self.status(pid)
            if status and status["connection"]["state"] == "connected":
                expected = ({"kind": "embedded", "state": "connected", "server": None} if standalone else
                            {"kind": "local_daemon", "state": "connected", "server": self.server_identity})
                if status["connection"] != expected:
                    raise Refused("actual_backend_identity_did_not_match_requested_mode")
            return ("OpenAI Codex" in text and "Trust this folder?" not in text
                    and status and status["connection"]["state"] == "connected")

        self.wait("tui_start", ready)
        return session, pane, pid

    def approve_owned_hooks(self, session: str, pane: str) -> None:
        if digest(self.codex_home / "hooks.json") != self.hooks_hash:
            raise Refused("reviewed_hooks_changed")
        if self.owned_hooks_approved():
            return  # The official startup review already performed this approval.
        self.keys(session, pane, "/hooks", literal=True)
        self.keys(session, pane, "Enter")
        self.wait("official_hooks_browser", lambda: "trust all" in self.screen(pane))
        self.keys(session, pane, "t")

        self.wait("official_hook_trust", self.owned_hooks_approved)
        self.keys(session, pane, "Escape")

    def owned_hooks_approved(self) -> bool:
        state = tomllib.loads((self.codex_home / "config.toml").read_text()).get("hooks", {}).get("state", {})
        return sum("trusted_hash" in value for value in state.values()) == 7

    def kernel_identity(self, pid: int) -> str:
        if sys.platform == "darwin":
            # Independent read of the same public XNU facts used by the contract. No
            # ps timestamps, JSON PID, socket filename or cached verdict authenticate it.
            class UniqueInfo(ctypes.Structure):
                _fields_ = [("executable_uuid", ctypes.c_ubyte * 16), ("unique_id", ctypes.c_uint64),
                            ("parent_unique_id", ctypes.c_uint64), ("reserved", ctypes.c_uint64 * 3)]
            libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            libc.sysctlbyname.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
                                         ctypes.c_void_p, ctypes.c_size_t]
            libc.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                         ctypes.c_void_p, ctypes.c_int]
            boot = ctypes.create_string_buffer(37)
            size = ctypes.c_size_t(37)
            if libc.sysctlbyname(b"kern.bootsessionuuid", boot, ctypes.byref(size), None, 0) or size.value != 37:
                raise Refused("kernel_boot_identity_unavailable")
            records = [UniqueInfo(), UniqueInfo()]
            for record in records:
                if ctypes.sizeof(record) != 56 or libc.proc_pidinfo(pid, 17, 1, ctypes.byref(record), 56) != 56:
                    raise Refused("kernel_process_identity_unavailable")
            if not records[0].unique_id or records[0].unique_id != records[1].unique_id:
                raise Refused("kernel_process_identity_changed")
            return f"macos:{str(uuid.UUID(boot.value.decode()))}:{records[0].unique_id}"
        if sys.platform.startswith("linux"):
            boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            records = [Path(f"/proc/{pid}/stat").read_text() for _ in range(2)]
            ticks = [record.rsplit(")", 1)[1].split()[19] for record in records]
            if ticks[0] != ticks[1] or int(ticks[0]) <= 0:
                raise Refused("kernel_process_identity_changed")
            return f"linux:{str(uuid.UUID(boot))}:{int(ticks[0])}"
        raise Refused("unsupported_kernel_identity_platform")

    def authenticate_peer(self, peer: socket.socket, pid: int) -> None:
        if sys.platform == "darwin":
            actual_pid = peer.getsockopt(0, 2)  # SOL_LOCAL / LOCAL_PEERPID, from XNU.
            uid, gid = ctypes.c_uint(), ctypes.c_uint()
            libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            if libc.getpeereid(peer.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
                raise Refused("status_peer_credentials_unavailable")
            actual_uid = uid.value
        else:
            actual_pid, actual_uid, _gid = struct.unpack("3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if actual_pid != pid or actual_uid != os.getuid():
            raise Refused("status_peer_identity_mismatch")

    def status(self, pid: int) -> dict | None:
        path = self.codex_home / "tui-status" / f"{pid}.sock"
        if not path.is_socket():
            return None
        try:
            before = self.kernel_identity(pid)
            if before != self.tui_identities.get(pid):
                raise Refused("owned_tui_incarnation_changed")
            identities = []
            for target, mode in ((path.parent, stat.S_ISDIR), (path, stat.S_ISSOCK)):
                info = target.lstat()
                if not mode(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                    raise Refused("status_endpoint_not_private")
                identities.append((info.st_dev, info.st_ino))
            with socket.socket(socket.AF_UNIX) as peer:
                peer.settimeout(self.remaining(0.5))
                peer.connect(str(path))
                self.authenticate_peer(peer, pid)
                peer.sendall(b'{"v":1,"type":"status"}\n')
                response = bytearray()
                while b"\n" not in response and len(response) <= 16384:
                    block = peer.recv(min(4096, 16385 - len(response)))
                    if not block:
                        return None
                    response.extend(block)
                if len(response) > 16384 or not response.endswith(b"\n"):
                    raise Refused("status_response_bound")
                if self.kernel_identity(pid) != before:
                    raise Refused("status_process_changed_during_query")
                for target, identity in zip((path.parent, path), identities):
                    info = target.lstat()
                    if (info.st_dev, info.st_ino) != identity:
                        raise Refused("status_endpoint_changed_during_query")
                return json.loads(response)
        except (OSError, json.JSONDecodeError):
            return None

    def mapping_ids(self) -> set[str]:
        if not self.metadata.exists():
            return set()
        return {row["session_id"] for row in json.loads(self.metadata.read_text())["mappings"]}

    def daemon_log(self, label: str | None = None) -> str:
        path = self.root / ((label or self.daemon_label) + ".log")
        if path.stat().st_size > MAX_LOG_BYTES:
            raise Refused("daemon_log_bound")
        return ANSI.sub("", path.read_text(errors="replace"))

    def turn(self, session: str, pane: str, pid: int, standalone: bool,
             before: set[str], trace_offset: int) -> dict:
        def observed():
            snapshot = self.status(pid)
            if not snapshot or snapshot.get("displayed_thread_id") not in snapshot.get("attached_thread_ids", []):
                return False
            kind = "embedded" if standalone else "local_daemon"
            if snapshot["connection"]["kind"] != kind:
                raise Refused("actual_backend_kind_did_not_match_requested_mode")
            if not standalone and (snapshot["connection"]["server"] != self.server_identity
                                   or self.kernel_identity(self.backend.pid) != self.server_identity["identity"]):
                raise Refused("shared_backend_was_not_owned_process")
            new = self.mapping_ids() - before
            if len(new) > 1:
                raise Refused("unexpected_extra_owned_thread")
            if not new:
                return False
            session_id = next(iter(new))
            if self.session_for_thread(snapshot["displayed_thread_id"]) != session_id:
                raise Refused("baseline_mapping_did_not_match_displayed_thread")
            log = self.daemon_log()
            registered = any("agent session registered" in line and "Codex" in line and session_id in line for line in log.splitlines())
            routed = any("agent route resolve" in line and session_id in line and f"pid={pid} " in line
                         and 'route="exact_live"' in line for line in log.splitlines())
            producer = standalone or any("shared Codex terminal authenticated" in line
                                        and f"producer_pid={self.backend.pid} " in line and f"terminal_pid={pid} " in line
                                        for line in log.splitlines())
            first_prompt = False
            stopped = False
            if self.trace.exists():
                with self.trace.open("rb") as stream:
                    stream.seek(trace_offset)
                    trace = stream.read(65536)
                    first_prompt = b" UserPromptSubmit ok\n" in trace
                    stopped = b" Stop ok\n" in trace
            answered = self.assistant_reply(snapshot["displayed_thread_id"])
            if registered and routed and producer and first_prompt and stopped and answered:
                return {"mode": kind, "first_user_prompt_hook": True, "registered": True,
                        "exact_live_route": True, "authenticated_producer": True,
                        "thread": snapshot["displayed_thread_id"], "pid": pid, "session_id": session_id}
            return False

        return self.wait("owned_turn_observation", observed, 45)

    def session_for_thread(self, thread: str) -> str | None:
        if not self.metadata.exists():
            return None
        return mapped_session(json.loads(self.metadata.read_text()), thread)

    def assistant_reply(self, thread: str) -> bool:
        return self.assistant_reply_count(thread) > 0

    def assistant_reply_count(self, thread: str) -> int:
        # Each fixture request emits a unique answer. Replayed/inherited copies of an
        # old answer cannot count as a new turn in register_selected_turn.
        replies: set[str] = set()
        if not re.fullmatch(r"[0-9a-f-]{36}", thread):
            raise Refused("invalid_owned_thread_id")
        files = list((self.codex_home / "sessions").rglob(f"rollout-*{thread}.jsonl"))
        if len(files) > 1:
            raise Refused("ambiguous_owned_rollout")
        for path in files:
            if path.stat().st_size > 4 * 1024 * 1024:
                raise Refused("owned_rollout_bound")
            for line in path.read_text().splitlines():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue  # A concurrently appended final line may be incomplete.
                payload = event.get("payload", {})
                if event.get("type") == "response_item" and payload.get("type") == "function_call":
                    raise Refused("fixture_unexpected_tool_call")
                if event.get("type") == "response_item" and payload.get("type") == "message" and payload.get("role") == "assistant":
                    text = "".join(block.get("text", "") for block in payload.get("content", []))
                    if re.fullmatch(re.escape(ANSWER) + r"-[1-9][0-9]*", text.strip()):
                        replies.add(text.strip())
        return len(replies)

    def failure_receipts(self) -> str:
        directory = Path(tempfile.mkdtemp(prefix="ciao-rehearse-receipts-", dir="/tmp"))
        directory.chmod(0o700)
        # Only this invocation's logs and fictional terminal are retained, never its fresh
        # host credentials, vendor auth/configuration or whole temporary home.
        for path in [*self.outputs, *self.logs.glob("*.trace.log")] if hasattr(self, "logs") else self.outputs:
            if path.is_file() and path.stat().st_size <= MAX_LOG_BYTES:
                target = directory / path.name
                shutil.copyfile(path, target)
                target.chmod(0o600)
        for index, session in enumerate(self.sessions):
            try:
                result = subprocess.run([self.tmux, "capture-pane", "-p", "-t", self.panes[session]],
                                        capture_output=True, timeout=2)
                if result.returncode == 0 and len(result.stdout) <= 65536:
                    target = directory / f"owned-tui-{index}.txt"
                    target.write_bytes(result.stdout)
                    target.chmod(0o600)
            except (OSError, subprocess.TimeoutExpired):
                pass
        for index, (pid, _start) in enumerate(self.tuis):
            try:
                snapshot = self.status(pid)
            except (Refused, OSError):
                continue
            if snapshot is not None:
                target = directory / f"owned-status-{index}.json"
                target.write_text(json.dumps(snapshot))
                target.chmod(0o600)
        return str(directory)

    def exercise(self) -> None:
        workspace_tui = None
        for index, standalone in enumerate((False, False, True)):
            before = self.mapping_ids()
            offset = self.trace.stat().st_size if self.trace.exists() else 0
            workspace = self.args.persisted_side_chats and index == 0
            session, pane, pid = self.start_tui(standalone, workspace=workspace)
            if workspace:
                workspace_tui = (session, pane, pid)
            self.approve_owned_hooks(session, pane)
            self.rows.append(self.turn(session, pane, pid, standalone, before, offset))
        if len({row["thread"] for row in self.rows}) != 3:
            raise Refused("threads_not_distinct")
        self.restart_observer()
        if workspace_tui is not None:
            self.exercise_side_chats(*workspace_tui)

    def selection(self, pid: int, expected: str | None = None,
                  after: Selection | None = None, excluding: set[str] | None = None) -> Selection:
        def selected():
            if self.kernel_identity(self.backend.pid) != self.server_identity["identity"]:
                raise Refused("owned_backend_incarnation_changed")
            result = live_selection(self.status(pid), self.server_identity, expected, after)
            return result if result and result.thread not in (excluding or set()) else None
        return self.wait("exact_workspace_selection", selected)

    def command(self, session: str, pane: str, text: str) -> None:
        # Complete a paste explicitly: rapid send-keys typing followed by Enter can
        # be absorbed by Codex's paste-burst detector as a newline, never submitting.
        self.keys(session, pane, "\x1b[200~" + text + "\x1b[201~", literal=True)
        self.keys(session, pane, "Enter")

    def open_chooser(self, session: str, pane: str) -> str:
        self.keys(session, pane, "F6")
        def loaded():
            screen = self.screen(pane)
            if ("New side chat" in screen and "Loading side chats" not in screen
                    and "Refreshing side chats" not in screen):
                return screen
            return None
        return self.wait("workspace_side_chooser", loaded)

    def choose_saved(self, session: str, pane: str, name: str) -> None:
        # Read the real chooser's order each time: upstream sorts saved chats by recency.
        screen = self.open_chooser(session, pane)
        names = chooser_labels(screen)
        if len(names) != 2 or set(names) != {"CiaoSide1", "CiaoSide2"}:
            raise Refused("saved_side_chat_choices_not_exact")
        self.keys(session, pane, "Home")
        self.wait("chooser_new_row_selected", lambda: "› + New side chat" in self.screen(pane))
        for _ in range(names.index(name) + 1):
            self.keys(session, pane, "Down")
        self.wait("chooser_saved_row_selected", lambda: re.search(
            r"›\s+○\s+" + re.escape(name) + r"\b", self.screen(pane)))
        self.keys(session, pane, "Enter")

    def register_selected_turn(self, session: str, pane: str, pid: int,
                               selected: Selection, label: str) -> Selection:
        offset = len(self.daemon_log())
        replies = self.assistant_reply_count(selected.thread)
        trace_offset = self.trace.stat().st_size
        requests = self.mock.requests
        self.command(session, pane, f"{label}. Reply only {ANSWER}. Do not use tools.")
        def registered():
            snapshot = live_selection(self.status(pid), self.server_identity, selected.thread)
            if not snapshot:
                return False
            session_id = self.session_for_thread(selected.thread)
            log = self.daemon_log()[offset:]
            producer = any("shared Codex terminal authenticated" in line
                           and f"producer_pid={self.backend.pid} " in line
                           and f"terminal_pid={pid} " in line for line in log.splitlines())
            with self.trace.open("rb") as stream:
                stream.seek(trace_offset)
                trace = stream.read(65536)
            hooks_complete = b" UserPromptSubmit ok\n" in trace and b" Stop ok\n" in trace
            if (session_id and (session_id, pid) in exact_route_pairs(log) and producer and hooks_complete
                    and self.mock.requests > requests
                    and self.assistant_reply_count(selected.thread) > replies):
                if snapshot.generation < selected.generation:
                    raise Refused("post_turn_selection_generation_regressed")
                # A completed resumed turn may reattach the same thread with a new
                # selection generation. The next cold check must start from this proof,
                # not the pre-prompt selection; it still forbids changes during the check.
                return snapshot
            return False
        return self.wait("exact_side_chat_turn_registration", registered, 45)

    def recover_selection(self, pid: int, selected: Selection | None, phase: str) -> None:
        """Cold route enumeration, NOT route-token use or a Codex restart."""
        expected = {(row["session_id"], row["pid"]) for row in self.rows[1:]}
        if selected:
            session_id = self.session_for_thread(selected.thread)
            if not session_id:
                raise Refused("selected_thread_not_registered")
            expected.add((session_id, pid))
        self.cold_checkpoint(pid, selected, phase, expected)

    def cold_checkpoint(self, pid: int, selected: Selection | None, phase: str,
                        expected: set[tuple[str, int]]) -> None:
        generation = selected.generation if selected else self.wait(
            "chooser_cleared_selection", lambda: cleared_selection(self.status(pid), self.server_identity))
        requests = self.mock.requests
        os.killpg(self.daemon.pid, signal.SIGINT)
        self.daemon.wait(timeout=self.remaining(8))
        self.daemon_label = "ciao-selection-" + str(len(self.side_evidence))
        self.daemon = self.spawn([str(self.ciao), "daemon"], self.daemon_label, self.daemon_env)
        session_id = self.session_for_thread(selected.thread) if selected else None
        self.wait("exact_selected_route_recovery", lambda: completed_recovery(self.daemon_log(), expected), 45)
        snapshot = self.status(pid)
        current_selection = live_selection(snapshot, self.server_identity, selected.thread) if selected else None
        current = (current_selection.generation if current_selection else
                   cleared_selection(snapshot, self.server_identity) if not selected else None)
        if current != generation or self.mock.requests != requests:
            raise Refused("selection_or_model_activity_changed_during_route_check")
        self.side_evidence.append({"phase": phase, "thread": selected.thread if selected else None, "pid": pid,
                                   "generation": generation, "session_id": session_id,
                                   "authenticated_status": True, "live_member": selected is not None,
                                   "status_snapshot": snapshot,
                                   "completed_observer_route_set_exact": True,
                                   "expected_routes": sorted(expected),
                                   "selected_route_recovered": (session_id, pid) in expected,
                                   "route_token_use": "not_exercised"})

    def idle_resume_checkpoint(self, pid: int, selected: Selection) -> None:
        requests, trace_size = self.mock.requests, self.trace.stat().st_size
        expected = {(row["session_id"], row["pid"]) for row in self.rows[1:]}
        session_id = self.session_for_thread(selected.thread)
        if not session_id:
            raise Refused("idle_resume_known_mapping_missing")
        expected.add((session_id, pid))
        self.cold_checkpoint(pid, selected, "idle-new-tui-before-prompt", expected)
        if self.mock.requests != requests or self.trace.stat().st_size != trace_size:
            raise Refused("idle_resume_checkpoint_generated_turn_or_hooks")
        self.side_lifecycle["idle_resume_routing"] = {
            "result": "recovered_before_any_fresh_hook",
            "contract_exception": False,
            "evidence_layer": "authenticated_status_and_route_log_only",
            "authenticated_thread": selected.thread,
            "new_prompts": 0,
            "route_token_use": "not_exercised",
        }

    def warm_focus_cycle(self, session: str, pane: str, pid: int, main: str,
                         sides: dict[str, str], previous: Selection) -> None:
        """Same observer endpoint lane. These selections are NOT Ciao route tokens.

        Public host APIs do not export terminal_plan or route listing/open via IPC.
        Paired terminal.open(target=agent_route) must separately prove at-use refusal;
        endpoint generations and log membership cannot stand in for that operation.
        """
        observer = self.daemon
        identity = self.kernel_identity(observer.pid)
        requests, trace_size = self.mock.requests, self.trace.stat().st_size
        cached_generations = [previous.generation]
        for name in ("main", "chooser", "CiaoSide1", "chooser", "CiaoSide2", "hidden-sidebar-main"):
            if name == "chooser":
                self.open_chooser(session, pane)
                self.wait("warm_chooser_cleared", lambda: cleared_selection(self.status(pid), self.server_identity))
                thread = None
            else:
                thread = sides.get(name, main)
                if name in sides:
                    self.choose_saved(session, pane, name)
                else:
                    self.keys(session, pane, "F7")
                    if name == "hidden-sidebar-main":
                        self.keys(session, pane, "F9")
                self.selection(pid, thread)
            snapshot = self.status(pid)
            generation = (cleared_selection(snapshot, self.server_identity) if thread is None else
                          snapshot_generation(snapshot, self.server_identity))
            if (generation is None or generation <= cached_generations[-1]
                    or (thread is not None and live_selection(snapshot, self.server_identity, thread) is None)):
                raise Refused("warm_selection_not_fresh")
            if (self.daemon is not observer or observer.poll() is not None
                    or self.kernel_identity(observer.pid) != identity
                    or self.kernel_identity(self.backend.pid) != self.server_identity["identity"]
                    or self.mock.requests != requests or self.trace.stat().st_size != trace_size):
                raise Refused("warm_observer_or_idle_fence_changed")
            self.side_evidence.append({
                "phase": "warm-focus-" + name, "thread": thread, "pid": pid,
                "observer_pid": observer.pid, "observer_kernel_identity": identity,
                "generation": generation, "status_snapshot": snapshot,
                "same_observer": True, "new_prompts": 0,
                "prior_status_generations_superseded": cached_generations.copy(),
                "hidden_threads_not_displayed": sorted({main, *sides.values()} - {thread}),
                "evidence_layer": "authenticated_endpoint_only",
                "route_token_use": "not_exercised",
            })
            # Even returning to the same UUID must advance beyond all cached revisions.
            cached_generations.append(generation)

    def exercise_side_chats(self, session: str, pane: str, pid: int) -> None:
        main = self.selection(pid, self.rows[0]["thread"])
        sides: dict[str, str] = {}
        previous = main
        for name in ("CiaoSide1", "CiaoSide2"):
            self.open_chooser(session, pane)
            self.keys(session, pane, "Home")
            self.wait("chooser_new_row_selected", lambda: "› + New side chat" in self.screen(pane))
            self.keys(session, pane, "Enter")
            selected = self.selection(pid, after=previous, excluding={main.thread, *sides.values()})
            if selected.thread in {main.thread, *sides.values()}:
                raise Refused("new_side_chat_identity_not_distinct")
            sides[name] = selected.thread
            selected = self.register_selected_turn(session, pane, pid, selected, name)
            self.command(session, pane, "/rename " + name)
            # Reopen the chooser to prove the persisted name, not an echoed /rename command.
            self.wait("renamed_side_chat", lambda: name in self.open_chooser(session, pane))
            self.keys(session, pane, "F7")
            previous = self.selection(pid, main.thread, after=selected)
        # Both chats must appear as saved choices before ending this actual TUI process.
        if set(chooser_labels(self.open_chooser(session, pane))) != set(sides):
            raise Refused("two_persisted_side_chats_not_listed")
        self.keys(session, pane, "F7")
        self.selection(pid, main.thread)
        old_pid, old_identity = pid, self.tui_identities[pid]
        self.side_lifecycle.update(main_thread=main.thread, saved_threads=sides.copy(),
                                   old_pid=old_pid, old_kernel_identity=old_identity)
        self.command(session, pane, "/quit")
        def exited():
            result = subprocess.run([self.tmux, "has-session", "-t", "=" + session],
                                    capture_output=True, timeout=self.remaining(2))
            current = subprocess.run(["/bin/ps", "-p", str(old_pid), "-o", "lstart="],
                                     capture_output=True, timeout=self.remaining(2))
            return result.returncode != 0 and not current.stdout.strip()
        self.wait("codex_tui_actually_exited", exited, 15)
        if (self.codex_home / "tui-status" / f"{old_pid}.sock").exists():
            raise Refused("exited_codex_status_socket_retained")
        session, pane, pid = self.start_tui(False, workspace=True, resume=main.thread)
        if self.tui_identities[pid] == old_identity:
            raise Refused("codex_tui_was_not_restarted")
        self.side_lifecycle.update(old_codex_exited=True, old_status_socket_removed=True,
                                   resumed_pid=pid, resumed_kernel_identity=self.tui_identities[pid])
        current = self.selection(pid, main.thread)
        if set(sides.values()) & set(self.status(pid)["attached_thread_ids"]):
            raise Refused("saved_but_unloaded_side_chat_claimed_live_after_restart")
        self.side_lifecycle["saved_threads_initially_unloaded"] = True
        # Require new-TUI admission before any prompt/hook. Endpoint/log checks do not
        # qualify paired at-use or visual PTY destination.
        self.idle_resume_checkpoint(pid, current)
        self.recover_selection(pid, current, "restarted-main")
        self.open_chooser(session, pane)
        self.recover_selection(pid, None, "restored-chooser-no-selection")
        for name, thread in sides.items():
            self.choose_saved(session, pane, name)
            current = self.selection(pid, thread, after=current)
            self.recover_selection(pid, current, "reopened-" + name)
        self.warm_focus_cycle(session, pane, pid, main.thread, sides, current)
        # Retain the separate cold lane. A fresh completed enumeration must name exactly
        # the selected UUID and the two unaffected baseline TUIs, never hidden main.
        for name in ("main", "CiaoSide1", "CiaoSide2", "hidden-sidebar-main"):
            if name in sides:
                self.choose_saved(session, pane, name)
                expected_thread = sides[name]
            else:
                self.keys(session, pane, "F7")
                expected_thread = main.thread
                if name == "hidden-sidebar-main":
                    self.keys(session, pane, "F9")
            current = self.selection(pid, expected_thread, after=current)
            self.recover_selection(pid, current, "focus-" + name)

    def restart_observer(self) -> None:
        if "CODEX_HOME" in self.daemon_env or self.codex_home == self.home / ".codex":
            raise Refused("custom_vendor_home_rehearsal_precondition")
        requests_before = self.mock.requests
        # Stop only the fixture daemon. Its terminal owners and shared backend remain live.
        os.killpg(self.daemon.pid, signal.SIGINT)
        self.daemon.wait(timeout=self.remaining(8))
        label = "ciao-daemon-restarted"
        self.daemon_label = label
        self.daemon = self.spawn([str(self.ciao), "daemon"], label, self.daemon_env)

        def recovered():
            if self.daemon.poll() is not None or self.backend.poll() is not None:
                raise Refused("owned_process_ended_during_restart")
            log = self.daemon_log(label)
            lines = log.splitlines()
            for row in self.rows:
                session_id, pid = row["session_id"], row["pid"]
                routed = any("agent route resolve" in line and session_id in line and f"pid={pid} " in line
                             and 'route="exact_live"' in line for line in lines)
                counts = [re.search(r"\bcount=(\d+)\b", line) for line in lines
                          if "Codex history reconciled" in line and session_id in line and "complete=true" in line]
                if not routed or not any(count and int(count.group(1)) >= 2 for count in counts):
                    return False
            return completed_recovery(log, {(row["session_id"], row["pid"]) for row in self.rows})

        self.wait("custom_home_idle_restart_history", recovered, 45)
        for pid, start in self.tuis:
            current = self.run(["/bin/ps", "-p", str(pid), "-o", "lstart="], "owned_tui_continuity").decode().strip()
            if current != start:
                raise Refused("owned_tui_changed_during_daemon_restart")
        if self.mock.requests != requests_before:
            raise Refused("history_recovery_started_a_model_request")
        for row in self.rows:
            row.update(custom_home_history_after_idle_restart=True, terminal_owner_preserved=True)

    def cleanup(self) -> dict[str, bool]:
        sessions_removed = True
        for session in reversed(self.sessions):
            try:
                subprocess.run([self.tmux, "kill-session", "-t", "=" + session],
                               stdin=subprocess.DEVNULL, capture_output=True, timeout=3)
                check = subprocess.run([self.tmux, "has-session", "-t", "=" + session],
                                       stdin=subprocess.DEVNULL, capture_output=True, timeout=3)
                sessions_removed &= check.returncode != 0
            except (OSError, subprocess.TimeoutExpired):
                sessions_removed = False
        tuis_removed = True
        for pid, start in self.tuis:
            try:
                current = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "lstart="], capture_output=True, timeout=2)
                if current.stdout.decode().strip() == start:
                    os.kill(pid, signal.SIGTERM)
                    end = time.monotonic() + 2
                    while time.monotonic() < end:
                        current = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "lstart="], capture_output=True, timeout=2)
                        if current.stdout.decode().strip() != start:
                            break
                        time.sleep(0.1)
                    else:
                        os.kill(pid, signal.SIGKILL)
                current = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "lstart="], capture_output=True, timeout=2)
                tuis_removed &= current.stdout.decode().strip() != start
            except ProcessLookupError:
                pass
            except (OSError, subprocess.TimeoutExpired):
                tuis_removed = False
        processes_removed = True
        for child in reversed(self.processes):
            if child.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(child.pid, signal.SIGINT)
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(child.pid, signal.SIGKILL)
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        processes_removed = False
            processes_removed &= child.poll() is not None
        self.mock.close()
        sockets_removed = True
        for path, device, inode in self.owned_sockets:
            try:
                metadata = path.lstat()
                if (metadata.st_dev, metadata.st_ino) == (device, inode) and stat.S_ISSOCK(metadata.st_mode):
                    path.unlink()
                else:
                    sockets_removed = False
            except FileNotFoundError:
                pass
            except OSError:
                sockets_removed = False
        unchanged = all(digest(path) == before for path, before in self.owner_hashes.items())
        return {"owned_sessions_removed": sessions_removed, "owned_tuis_removed": tuis_removed,
                "owned_background_processes_removed": processes_removed,
                "owned_backend_socket_removed": sockets_removed,
                "owner_files_unchanged": unchanged}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ciao-binary", type=Path, required=True)
    parser.add_argument("--codex-binary", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--persisted-side-chats", action="store_true",
                        help="0.169+ on macOS: loopback-fenced side chats, Codex restart, warm endpoint/cold route checks (not route-token use); use --timeout 600")
    parser.add_argument("--allow-observer-network", action="store_true",
                        help="explicitly permit owned Ciao observer/children normal network and macOS ps; vendor TUI/backend stay fenced, no all-process attestation")
    args = parser.parse_args()
    if args.allow_observer_network and not args.persisted_side_chats:
        parser.error("--allow-observer-network requires --persisted-side-chats")
    if not 30 <= args.timeout <= 600:
        parser.error("--timeout must be between 30 and 600 seconds")
    args.ciao_binary = args.ciao_binary.resolve()
    args.codex_binary = args.codex_binary.resolve()
    report: dict[str, object] = {"external_model_calls": 0, "subscription_credentials_used": False,
                                "qualification_complete": False,
                                "pass_scope": "harness_checks_only_not_candidate_qualification",
                                "route_token_use": "not_exercised_requires_paired_terminal_open",
                                "limitations": ["warm_route_token_revalidation_not_tested",
                                                "idle_new_tui_typed_and_visual_routing_not_qualified"],
                                "harness_sha256": digest(Path(__file__)),
                                "outbound_ip_fence": "loopback_only" if args.persisted_side_chats else "proxy_only"}
    if args.allow_observer_network:
        report["outbound_ip_fence"] = "vendor_tui_and_backend_loopback_only; owned_ciao_and_history_children_unfenced"
        report["external_model_calls"] = "mock_only_requested; no_real_credentials; not_all_process_network_attestation"
    rehearsal = None
    with tempfile.TemporaryDirectory(prefix="ciao-rehearse-", dir="/tmp") as directory:
        try:
            rehearsal = Rehearsal(args, Path(directory))
            rehearsal.initialize()
            rehearsal.exercise()
            if rehearsal.mock.over_budget:
                raise Refused("local_http_budget_exceeded")
            report["modes"] = [{key: value for key, value in row.items() if key not in ("thread", "pid", "session_id")}
                               for row in rehearsal.rows]
            report["same_shared_backend_two_distinct_threads"] = True
            report["persisted_side_chats"] = {"requested": args.persisted_side_chats,
                                               "checkpoints": rehearsal.side_evidence,
                                               "evidence_layer": "warm authenticated endpoint; cold daemon enumeration; NOT route-token use or phone UI"}
            report["candidate_sha256"] = rehearsal.source_hashes
            report["local_fixture_requests"] = rehearsal.mock.requests
            report["passed"] = True
        except Refused as error:
            report.update(passed=False, failure=str(error))
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            report.update(passed=False, failure="owned_harness_operation_failed")
        except KeyboardInterrupt:
            report.update(passed=False, failure="rehearsal_interrupted")
        finally:
            if rehearsal is not None:
                report["candidate_sha256"] = rehearsal.source_hashes
                report["local_fixture_requests"] = rehearsal.mock.requests
                report["local_http_requests"] = rehearsal.mock.http_requests
                if not report.get("passed"):
                    with contextlib.suppress(OSError, Refused, KeyError, subprocess.SubprocessError):
                        report["failure_receipts"] = rehearsal.failure_receipts()
                report["persisted_side_chat_checkpoints"] = rehearsal.side_evidence
                report["persisted_side_chat_lifecycle"] = rehearsal.side_lifecycle
                report["cleanup"] = rehearsal.cleanup()
                if not all(report["cleanup"].values()):
                    report["passed"] = False
    print(json.dumps(report, sort_keys=True))
    return 0 if report.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
