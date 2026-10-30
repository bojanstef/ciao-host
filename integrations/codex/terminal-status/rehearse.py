#!/usr/bin/env python3
"""Exercise real Codex TUIs and Ciao against an owned, local Responses fixture.

No account, service installation, production configuration or real model is used. The
only trust approval is the official /hooks UI in the disposable vendor home, after the
installed hook commands have been checked. Every process and tmux session is owned by
this invocation. Run after `cargo build --locked -p ciao-host`.
"""

from __future__ import annotations

import argparse
import contextlib
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
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import uuid


ANSWER = "CiaoLocalRehearsal"
MAX_LOG_BYTES = 8 * 1024 * 1024
MAX_HTTP_REQUESTS = 12
ANSI = re.compile(r"\x1b\[[0-9;]*m")


class Refused(RuntimeError):
    """A fixed category, with no terminal, request or credential content."""


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
        self.lock = threading.Lock()

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args: object) -> None:
                pass

            def do_GET(self) -> None:
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
                self.connection.settimeout(3)
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
                with fixture.lock:
                    fixture.requests += 1
                    number = fixture.requests
                if number > MAX_HTTP_REQUESTS:
                    self.send_error(429)
                    return
                response_id = f"ciao-fixture-{number}"
                events = [
                    {"type": "response.created", "response": {"id": response_id}},
                    {"type": "response.output_item.done", "item": {
                        "type": "message", "role": "assistant", "id": f"message-{number}",
                        "content": [{"type": "output_text", "text": ANSWER}],
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
        try:
            child = subprocess.Popen(argv, env=self.env if env is None else env, cwd=self.project,
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
        config = f'''model = "gpt-5.4"
model_provider = "ciao_fixture"
approval_policy = "never"
sandbox_mode = "read-only"
cli_auth_credentials_store = "file"
[features]
hooks = true
daemon_auto_start = false
apps = false
remote_plugin = false
[tui]
pet = "disabled"
[model_providers.ciao_fixture]
name = "Ciao local fixture"
base_url = "{self.mock.url}"
wire_api = "responses"
requires_openai_auth = false
supports_websockets = false
request_max_retries = 0
stream_max_retries = 0
'''
        (self.codex_home / "config.toml").write_text(config)
        self.run([str(self.ciao), "agent", "install", "codex"], "hook_install", 20)
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

    def tmux_command(self, *args: str) -> bytes:
        # Use the real account socket so the candidate's unchanged provider can resolve it.
        # No global options, focus changes, server shutdown or existing session are touched.
        return self.run([self.tmux, *args], "owned_tmux")

    def pane_value(self, pane: str, format_string: str) -> str:
        return self.tmux_command("display-message", "-p", "-t", pane, format_string).decode().strip()

    def keys(self, session: str, pane: str, *keys: str, literal: bool = False) -> None:
        if session not in self.sessions or self.pane_value(pane, "#{session_name}") != session:
            raise Refused("input_target_not_owned")
        self.tmux_command("send-keys", "-t", pane, *( ["-l"] if literal else []), *keys)

    def screen(self, pane: str) -> str:
        return self.tmux_command("capture-pane", "-p", "-t", pane).decode(errors="replace")

    def start_tui(self, standalone: bool) -> tuple[str, str, int]:
        session = "ciao-rehearse-" + uuid.uuid4().hex[:12]
        env_args = [f"{key}={value}" for key, value in self.env.items()]
        self.tmux_command("new-session", "-d", "-E", "-s", session, "-x", "120", "-y", "40", "-c", str(self.project),
                          "/usr/bin/env", "-i", *env_args, str(self.codex), *( ["--no-daemon"] if standalone else []),
                          f"Reply only {ANSWER}. Do not use tools.")
        self.sessions.append(session)
        pane = self.pane_value("=" + session, "#{pane_id}")
        self.panes[session] = pane
        pid = int(self.pane_value(pane, "#{pane_pid}"))
        start = self.run(["/bin/ps", "-p", str(pid), "-o", "lstart="], "owned_tui_identity").decode().strip()
        self.tuis.append((pid, start))
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

    def status(self, pid: int) -> dict | None:
        path = self.codex_home / "tui-status" / f"{pid}.sock"
        if not path.is_socket():
            return None
        try:
            with socket.socket(socket.AF_UNIX) as peer:
                peer.settimeout(0.5)
                peer.connect(str(path))
                peer.sendall(b'{"v":1,"type":"status"}\n')
                response = bytearray()
                while b"\n" not in response and len(response) <= 16384:
                    block = peer.recv(min(4096, 16385 - len(response)))
                    if not block:
                        return None
                    response.extend(block)
                if len(response) > 16384 or not response.endswith(b"\n"):
                    raise Refused("status_response_bound")
                return json.loads(response)
        except (OSError, json.JSONDecodeError):
            return None

    def mapping_ids(self) -> set[str]:
        if not self.metadata.exists():
            return set()
        return {row["session_id"] for row in json.loads(self.metadata.read_text())["mappings"]}

    def daemon_log(self, label: str = "ciao-daemon") -> str:
        path = self.root / (label + ".log")
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
            if not standalone and snapshot["connection"]["server"]["pid"] != self.backend.pid:
                raise Refused("shared_backend_was_not_owned_process")
            new = self.mapping_ids() - before
            if len(new) > 1:
                raise Refused("unexpected_extra_owned_thread")
            if not new:
                return False
            session_id = next(iter(new))
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

    def assistant_reply(self, thread: str) -> bool:
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
                    if text.strip() == ANSWER:
                        return True
        return False

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
            snapshot = self.status(pid)
            if snapshot is not None:
                target = directory / f"owned-status-{index}.json"
                target.write_text(json.dumps(snapshot))
                target.chmod(0o600)
        return str(directory)

    def exercise(self) -> None:
        for standalone in (False, False, True):
            before = self.mapping_ids()
            offset = self.trace.stat().st_size if self.trace.exists() else 0
            session, pane, pid = self.start_tui(standalone)
            self.approve_owned_hooks(session, pane)
            self.rows.append(self.turn(session, pane, pid, standalone, before, offset))
        if len({row["thread"] for row in self.rows}) != 3:
            raise Refused("threads_not_distinct")
        self.restart_observer()

    def restart_observer(self) -> None:
        if "CODEX_HOME" in self.daemon_env or self.codex_home == self.home / ".codex":
            raise Refused("custom_vendor_home_rehearsal_precondition")
        requests_before = self.mock.requests
        # Stop only the fixture daemon. Its terminal owners and shared backend remain live.
        os.killpg(self.daemon.pid, signal.SIGINT)
        self.daemon.wait(timeout=self.remaining(8))
        label = "ciao-daemon-restarted"
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
            return any("re-adopted attached agent sessions after startup" in line and "readopted=3" in line
                       for line in lines)

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
    args = parser.parse_args()
    if not 30 <= args.timeout <= 600:
        parser.error("--timeout must be between 30 and 600 seconds")
    args.ciao_binary = args.ciao_binary.resolve()
    args.codex_binary = args.codex_binary.resolve()
    report: dict[str, object] = {"external_model_calls": 0, "subscription_credentials_used": False}
    rehearsal = None
    with tempfile.TemporaryDirectory(prefix="ciao-rehearse-", dir="/tmp") as directory:
        try:
            rehearsal = Rehearsal(args, Path(directory))
            rehearsal.initialize()
            rehearsal.exercise()
            report["modes"] = [{key: value for key, value in row.items() if key not in ("thread", "pid", "session_id")}
                               for row in rehearsal.rows]
            report["same_shared_backend_two_distinct_threads"] = True
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
                if not report.get("passed"):
                    with contextlib.suppress(OSError, subprocess.SubprocessError):
                        report["failure_receipts"] = rehearsal.failure_receipts()
                report["cleanup"] = rehearsal.cleanup()
                if not all(report["cleanup"].values()):
                    report["passed"] = False
    print(json.dumps(report, sort_keys=True))
    return 0 if report.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
