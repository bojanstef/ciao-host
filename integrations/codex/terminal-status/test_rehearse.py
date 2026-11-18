"""Harness regressions: no vendor binary, account, tmux, daemon or Cargo build."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import rehearse


MAIN = "11111111-1111-4111-8111-111111111111"
SIDE1 = "22222222-2222-4222-8222-222222222222"
SIDE2 = "33333333-3333-4333-8333-333333333333"
FIXTURES = json.loads(Path(__file__).with_name("examples.json").read_text())
SERVER = FIXTURES["shared"]["connection"]["server"]


def snapshot(thread=SIDE1, generation=3):
    value = copy.deepcopy(FIXTURES["shared"])
    value.update(displayed_thread_id=thread, generation=generation,
                 attached_thread_ids=[MAIN, SIDE1, SIDE2])
    return value


def route(session, pid, continuity="exact_live"):
    return f'agent route resolve session={session} pid={pid} route="{continuity}"\n'


def complete(count):
    return f"re-adopted attached agent sessions after startup readopted={count}\n"


class SelectionTests(unittest.TestCase):
    def test_exact_each_thread_and_generation(self):
        previous = rehearse.Selection(MAIN, 2)
        for number, thread in enumerate((SIDE1, SIDE2, MAIN), 3):
            current = rehearse.live_selection(snapshot(thread, number), SERVER, thread, previous)
            self.assertEqual(current, rehearse.Selection(thread, number))
            previous = current

    def test_attached_hidden_main_is_not_selected_side(self):
        self.assertIsNone(rehearse.live_selection(snapshot(MAIN), SERVER, SIDE1))
        self.assertIsNone(rehearse.live_selection(snapshot(SIDE1), SERVER, SIDE2))

    def test_stale_old_selection_and_generation_refused(self):
        for generation in (1, 2, 3):
            with self.subTest(generation=generation):
                self.assertIsNone(rehearse.live_selection(
                    snapshot(SIDE2, generation), SERVER, SIDE2, rehearse.Selection(SIDE1, 3)))

    def test_historical_unloaded_and_restoring_cannot_pass(self):
        for displayed, attached in ((SIDE1, []), (SIDE1, [MAIN]), (None, [MAIN, SIDE1]),
                                    (None, []), (MAIN, [MAIN, SIDE1])):
            value = snapshot()
            value.update(displayed_thread_id=displayed, attached_thread_ids=attached)
            self.assertIsNone(rehearse.live_selection(value, SERVER, SIDE1))

    def test_cleared_chooser_is_not_hidden_main_or_missing_status(self):
        value = snapshot()
        value["displayed_thread_id"] = None
        self.assertEqual(rehearse.cleared_selection(value, SERVER), 3)
        for bad in (None, {}, snapshot(MAIN), snapshot(SIDE1)):
            self.assertIsNone(rehearse.cleared_selection(bad, SERVER))
        del value["displayed_thread_id"]
        self.assertIsNone(rehearse.cleared_selection(value, SERVER))

    def test_shared_ownership_connection_and_kernel_incarnation_required(self):
        for fixture in (FIXTURES["embedded"], FIXTURES["disconnected"]):
            self.assertIsNone(rehearse.live_selection(fixture, SERVER))
        for key, value in (("kind", "remote"), ("state", "disconnected"),
                           ("server", None), ("server", {**SERVER, "pid": 999}),
                           ("server", {**SERVER, "identity": SERVER["identity"] + "0"})):
            candidate = snapshot()
            candidate["connection"][key] = value
            self.assertIsNone(rehearse.live_selection(candidate, SERVER))

    def test_malformed_and_bound_values_do_not_pass(self):
        for candidate in (None, [], {}, {"v": True}):
            self.assertIsNone(rehearse.live_selection(candidate, SERVER))
        for key, value in (("generation", True), ("generation", 0), ("generation", "3"),
                           ("displayed_thread_id", "not-a-thread"),
                           ("attached_thread_ids", [SIDE1, SIDE1]),
                           ("attached_thread_ids", [SIDE1, {}]),
                           ("attached_thread_ids", [SIDE1, "bad"]),
                           ("attached_thread_ids", [SIDE1] * 65)):
            candidate = snapshot()
            candidate[key] = value
            self.assertIsNone(rehearse.live_selection(candidate, SERVER), (key, value))


class IdentityAndRouteTests(unittest.TestCase):
    def metadata(self):
        key = bytes(range(32))
        rows = []
        for index, thread in enumerate((MAIN, SIDE1, SIDE2)):
            # Independently spell the host's NUL-terminated domain and length framing.
            hasher = hashlib.sha256()
            hasher.update(b"ciao-agent-identity-v1" + bytes([0]))
            hasher.update(key)
            hasher.update(len(thread.encode()).to_bytes(8, "big"))
            hasher.update(thread.encode())
            rows.append({"upstream_digest": hasher.hexdigest(), "session_id": f"session-{index}",
                         "adapter_family": "Codex"})
        return {"key": key.hex(), "mappings": list(reversed(rows))}

    def test_exact_mapping_not_latest_mapping(self):
        document = self.metadata()
        for index, thread in enumerate((MAIN, SIDE1, SIDE2)):
            self.assertEqual(rehearse.mapped_session(document, thread), f"session-{index}")
        self.assertIsNone(rehearse.mapped_session(document, "unknown"))

    def test_wrong_family_and_ambiguous_mapping_refused(self):
        document = self.metadata()
        document["mappings"][0]["adapter_family"] = "Claude"
        self.assertIsNone(rehearse.mapped_session(document, SIDE2))
        document = self.metadata()
        document["mappings"].append(document["mappings"][0])
        with self.assertRaises(rehearse.Refused):
            rehearse.mapped_session(document, SIDE2)

    def test_complete_exact_set_is_positive_evidence(self):
        expected = {("s-main", 10), ("s-baseline", 20), ("s-standalone", 30)}
        log = "".join(route(session, pid) for session, pid in expected) + complete(3)
        self.assertTrue(rehearse.completed_recovery(log, expected))
        self.assertTrue(rehearse.completed_recovery(log + route("s-main", 10), expected))

    def test_enumeration_waits_for_delayed_route_commit_within_bound(self):
        expected = {("selected", 10), ("baseline", 20)}
        partial = route("selected", 10) + complete(2)
        logs = iter([partial, partial, partial + route("baseline", 20)])
        r = object.__new__(rehearse.Rehearsal)
        r.deadline, r.outputs = 100, []
        with patch.object(rehearse.time, "monotonic", side_effect=range(20)), \
                patch.object(rehearse.time, "sleep"):
            self.assertTrue(r.wait("routes", lambda: rehearse.completed_recovery(next(logs), expected), 10))

    def test_missing_route_still_refuses_at_predicate_deadline(self):
        r = object.__new__(rehearse.Rehearsal)
        r.deadline, r.outputs = 100, []
        with patch.object(rehearse.time, "monotonic", side_effect=range(20)), \
                patch.object(rehearse.time, "sleep"), \
                self.assertRaisesRegex(rehearse.Refused, "routes_timeout"):
            r.wait("routes", lambda: rehearse.completed_recovery(complete(1), {("missing", 10)}), 5)

    def test_empty_logs_or_only_routes_do_not_prove_recovery(self):
        self.assertFalse(rehearse.completed_recovery("", {("selected", 10)}))
        self.assertFalse(rehearse.completed_recovery(route("selected", 10), {("selected", 10)}))

    def test_hidden_main_old_pid_wrong_thread_extra_route_and_incomplete_counts_fail(self):
        expected = {("selected-side", 10)}
        for log in (route("hidden-main", 10) + complete(1),
                    route("selected-side", 9) + complete(1),
                    route("selected-side", 10) + route("hidden-main", 10) + complete(2),
                    route("selected-side", 10) + route("hidden-main", 10) + complete(1),
                    route("selected-side", 10, "none") + complete(1),
                    route("selected-side", 10) + complete(0),
                    route("selected-side", 10) + complete(1) + complete(1)):
            with self.subTest(log=log), self.assertRaises(rehearse.Refused):
                rehearse.completed_recovery(log, expected)

    def test_route_parser_exact_fields_not_substrings(self):
        log = route("selected-other", 100) + route('"selected"', 10) + route("selected", 10, "none")
        self.assertEqual(rehearse.exact_route_pairs(log), {("selected-other", 100), ("selected", 10)})

    def test_chooser_order_comes_from_rows_not_transcript_or_fixed_recency(self):
        screen = "Rename CiaoSide1\n  ○ CiaoSide2\n› ○ CiaoSide1\n Reply CiaoSide2\n"
        self.assertEqual(rehearse.chooser_labels(screen), ["CiaoSide2", "CiaoSide1"])
        self.assertEqual(rehearse.chooser_labels("CiaoSide1\nCiaoSide2"), [])


class StartupTests(unittest.TestCase):
    def test_observer_network_opt_in_never_unfences_vendor_or_non_daemon(self):
        with tempfile.TemporaryDirectory() as directory:
            r = object.__new__(rehearse.Rehearsal)
            r.root = r.project = Path(directory)
            r.ciao, r.codex = r.root / "ciao", r.root / "codex"
            r.env = {"HOME": str(r.root), "OPENAI_API_KEY": "fake", "HTTPS_PROXY": "deny"}
            r.network_prefix = ["sandbox-exec", "-p", "loopback"]
            r.outputs, r.processes = [], []
            for allowed in (False, True):
                r.args = SimpleNamespace(allow_observer_network=allowed)
                for argv in ([str(r.ciao), "daemon"], [str(r.codex), "app-server"],
                             [str(r.ciao), "agent", "status"]):
                    with patch.object(rehearse.subprocess, "Popen") as popen:
                        r.spawn(argv, "owned")
                        observer = allowed and argv == [str(r.ciao), "daemon"]
                        self.assertEqual(popen.call_args.args[0], argv if observer else r.network_prefix + argv)
                        env = popen.call_args.kwargs["env"]
                        self.assertEqual("HTTPS_PROXY" not in env, observer)
                        self.assertEqual(env["HOME"], str(r.root))
                        self.assertEqual(env["OPENAI_API_KEY"], "fake")
                        self.assertEqual(r.env["HTTPS_PROXY"], "deny")

    def test_workspace_preferences_are_file_config_not_daemon_excluding_overrides(self):
        config = rehearse.tomllib.loads(rehearse.vendor_config("http://127.0.0.1:1234/v1", True))
        self.assertEqual(config["tui"]["alternate_screen"], "always")
        self.assertEqual(config["tui"]["keymap"]["global"], {
            "focus_sidebar_tabs": "f6", "focus_main_composer": "f7",
            "focus_sidebar_content": "f8", "hide_pane": "f9"})
        # The daemon compares feature overrides even though their syntax is permitted.
        self.assertTrue(config["features"]["tui_workspace"])
        baseline = rehearse.tomllib.loads(rehearse.vendor_config("local", False))
        self.assertFalse(baseline["features"]["tui_workspace"])
        self.assertEqual(config["model_providers"]["ciao_fixture"]["base_url"], "http://127.0.0.1:1234/v1")
        for standalone in (True, False):
            options = rehearse.tui_options(standalone, True, MAIN)
            self.assertEqual("--no-daemon" in options, standalone)
            overrides = [options[index + 1] for index, value in enumerate(options) if value == "-c"]
            self.assertEqual(overrides, ["features.tui_workspace=true", "tui.fullscreen_transcript=true"])
            self.assertEqual(options[-2:], ["resume", MAIN])
        self.assertNotIn("-c", rehearse.tui_options(False, False, None))
        self.assertEqual(rehearse.tomllib.loads(rehearse.vendor_config("local", False))["tui"],
                         {"pet": "disabled"})

    def test_initialize_config_precedes_backend_and_install_gets_only_60_seconds(self):
        with tempfile.TemporaryDirectory() as directory:
            r = object.__new__(rehearse.Rehearsal)
            r.root = Path(directory)
            r.project, r.codex_home = r.root / "project", r.root / "codex"
            r.project.mkdir()
            r.codex_home.mkdir()
            build = r.root / "build"
            build.mkdir()
            (build / "libciao_host.rlib").touch()
            (build / "deps").mkdir()
            r.args = SimpleNamespace(ciao_binary=build / "ciao", persisted_side_chats=True)
            r.ciao, r.codex, r.rustc = build / "ciao", build / "codex", "mock-rustc"
            r.mock = SimpleNamespace(url="http://127.0.0.1:1/v1")
            r.env = {"HOME": str(r.root), "CODEX_HOME": str(r.codex_home)}
            logs = r.root / "logs"
            logs.mkdir()
            def run(_argv, label, _seconds=10):
                if label == "identity_init":
                    return f"{r.root / 'metadata'}\n{logs}\n{r.root / 'socket'}\n".encode()
                if label == "hook_install":
                    config = rehearse.tomllib.loads((r.codex_home / "config.toml").read_text())
                    self.assertEqual(config["tui"]["keymap"]["global"]["focus_sidebar_tabs"], "f6")
                    (r.codex_home / "hooks.json").write_text(json.dumps({"hooks": {"event": [{
                        "hooks": [{"command": f"'{r.ciao}' __codex-hook"}] * 7}]}}))
                return b""
            r.run = Mock(side_effect=run)
            r.wait = Mock()
            def spawn(_argv, label, *_args):
                if label == "codex-backend":
                    config = rehearse.tomllib.loads((r.codex_home / "config.toml").read_text())
                    self.assertTrue(config["features"]["tui_workspace"])
                    raise rehearse.Refused("stop_before_vendor_launch")
                return Mock()
            r.spawn = Mock(side_effect=spawn)
            with self.assertRaisesRegex(rehearse.Refused, "stop_before_vendor_launch"):
                r.initialize()
            installs = [call for call in r.run.call_args_list if call.args[1] == "hook_install"]
            self.assertEqual(len(installs), 1)
            self.assertEqual(installs[0].args[2], 60)
            self.assertEqual(r.spawn.call_args.args[1], "codex-backend")

    def test_operation_timeout_remains_clamped_to_global_deadline(self):
        r = object.__new__(rehearse.Rehearsal)
        r.deadline = 600
        with patch.object(rehearse.time, "monotonic", return_value=570):
            self.assertEqual(r.remaining(60), 30)
        with patch.object(rehearse.time, "monotonic", return_value=600):
            with self.assertRaisesRegex(rehearse.Refused, "rehearsal_deadline"):
                r.remaining(60)

    def start_fixture(self, connection, standalone=False):
        r = object.__new__(rehearse.Rehearsal)
        r.env, r.network_prefix = {}, []
        r.codex, r.project = Path("/owned/codex"), Path("/owned/project")
        r.sessions, r.panes, r.tuis, r.tui_identities = [], {}, [], {}
        r.server_identity = SERVER
        r.tmux_command = Mock(return_value=b"%20\n")
        r.pane_value = Mock(return_value="20")
        r.run = Mock(return_value=b"start")
        r.kernel_identity = Mock(return_value="owned-tui-incarnation")
        r.screen = Mock(return_value="OpenAI Codex")
        r.status = Mock(return_value={"connection": connection})
        r.wait = lambda _label, predicate: self.assertTrue(predicate())
        r.start_tui(standalone, workspace=True)
        return r

    def test_shared_start_refuses_embedded_fallback_wrong_pid_and_wrong_incarnation(self):
        for connection in ({"kind": "embedded", "state": "connected", "server": None},
                           {"kind": "local_daemon", "state": "connected", "server": {**SERVER, "pid": 999}},
                           {"kind": "local_daemon", "state": "connected", "server": {**SERVER, "identity": "wrong"}}):
            with self.subTest(connection=connection), self.assertRaisesRegex(
                    rehearse.Refused, "actual_backend_identity_did_not_match_requested_mode"):
                self.start_fixture(connection)

    def test_standalone_and_owned_shared_start_remain_distinct(self):
        for standalone, connection in ((True, {"kind": "embedded", "state": "connected", "server": None}),
                                       (False, {"kind": "local_daemon", "state": "connected", "server": SERVER})):
            r = self.start_fixture(connection, standalone)
            self.assertEqual("--no-daemon" in r.tmux_command.call_args.args, standalone)
            self.assertNotIn('tui.alternate_screen="always"', r.tmux_command.call_args.args)
            self.assertIn("-P", r.tmux_command.call_args.args)
            self.assertEqual(list(r.panes.values()), ["%20"])

    def test_isolated_launch_keeps_only_the_new_tmux_child_markers(self):
        r = self.start_fixture({"kind": "local_daemon", "state": "connected", "server": SERVER})
        args = r.tmux_command.call_args.args
        shell = args.index("/bin/sh")
        # Execute the actual launcher prefix without a vendor, tmux or daemon.
        command = [*args[shell:shell + 4], "HOME=/owned/home", "/usr/bin/env"]
        child_env = {"TMUX": "/owned/socket,123,4", "TMUX_PANE": "%20", "UNRELATED": "not-forwarded"}
        result = subprocess.run(command, env=child_env, capture_output=True, text=True, check=True, timeout=3)
        values = dict(line.split("=", 1) for line in result.stdout.splitlines())
        self.assertEqual(values["TMUX"], child_env["TMUX"])
        self.assertEqual(values["TMUX_PANE"], "%20")
        self.assertEqual(values["HOME"], "/owned/home")
        self.assertNotIn("UNRELATED", values)
        for missing in ("TMUX", "TMUX_PANE"):
            with self.subTest(missing=missing):
                incomplete = {key: value for key, value in child_env.items() if key != missing}
                refused = subprocess.run(command, env=incomplete, capture_output=True, timeout=3)
                self.assertNotEqual(refused.returncode, 0)

    def test_empty_or_foreign_pane_never_falls_back_to_tmux_current_target(self):
        r = object.__new__(rehearse.Rehearsal)
        r.sessions, r.panes = ["owned"], {"owned": "%20"}
        r.pane_value, r.tmux_command = Mock(return_value="owned"), Mock()
        for pane in ("", "%21", "owned", "%20:0"):
            with self.subTest(pane=pane), self.assertRaisesRegex(rehearse.Refused, "input_target_not_owned"):
                r.keys("owned", pane, "Enter")
        r.tmux_command.assert_not_called()
        r.keys("owned", "%20", "Enter")
        r.tmux_command.assert_called_once_with("send-keys", "-t", "%20", "Enter")


class HarnessFlowTests(unittest.TestCase):
    def test_commands_use_bracketed_paste_not_a_timed_typing_burst(self):
        r = object.__new__(rehearse.Rehearsal)
        r.keys = Mock()
        r.command("owned", "%20", "fictional prompt")
        self.assertEqual([call.args for call in r.keys.call_args_list], [
            ("owned", "%20", "\x1b[200~fictional prompt\x1b[201~"),
            ("owned", "%20", "Enter")])
        self.assertTrue(r.keys.call_args_list[0].kwargs["literal"])

    def side_flow(self, home, new_identity="new-incarnation"):
        rehearsal = object.__new__(rehearse.Rehearsal)
        rehearsal.rows = [{"thread": MAIN}]
        rehearsal.tmux = "/fixture/tmux"
        rehearsal.codex_home = Path(home)
        rehearsal.tui_identities = {10: "old-incarnation", 20: new_identity}
        rehearsal.side_lifecycle = {}
        rehearsal.open_chooser = Mock(return_value="  ○ CiaoSide1\n  ○ CiaoSide2")
        rehearsal.keys = Mock()
        rehearsal.screen = Mock(return_value="› + New side chat")
        rehearsal.command = Mock()
        rehearsal.register_selected_turn = Mock(side_effect=lambda _session, _pane, _pid, selected, _label:
                                                rehearse.Selection(selected.thread, selected.generation + 2))
        rehearsal.recover_selection = Mock()
        rehearsal.idle_resume_checkpoint = Mock()
        rehearsal.warm_focus_cycle = Mock()
        rehearsal.flow = Mock()
        for name in ("register_selected_turn", "recover_selection", "idle_resume_checkpoint", "warm_focus_cycle"):
            rehearsal.flow.attach_mock(getattr(rehearsal, name), name)
        rehearsal.choose_saved = Mock()
        rehearsal.remaining = lambda seconds: seconds
        rehearsal.start_tui = Mock(return_value=("new-session", "%20", 20))
        value = snapshot(MAIN)
        value["attached_thread_ids"] = [MAIN]
        rehearsal.status = Mock(return_value=value)
        generation = 0
        def selection(_pid, expected=None, after=None, excluding=None):
            nonlocal generation
            generation += 1
            thread = expected or next(item for item in (SIDE1, SIDE2) if item not in excluding)
            return rehearse.Selection(thread, generation)
        rehearsal.selection = selection
        rehearsal.wait = lambda _label, predicate, *_args: self.assertTrue(predicate())
        return rehearsal

    def test_extended_flow_actually_quits_codex_resumes_main_and_reopens_both(self):
        with tempfile.TemporaryDirectory() as directory:
            rehearsal = self.side_flow(directory)
            with patch.object(rehearse.subprocess, "run", return_value=Mock(returncode=1, stdout=b"")):
                rehearsal.exercise_side_chats("old-session", "%10", 10)
        rehearsal.start_tui.assert_called_once_with(False, workspace=True, resume=MAIN)
        self.assertIn(("old-session", "%10", "/quit"),
                      [call.args for call in rehearsal.command.call_args_list])
        self.assertEqual([call.args[3].thread for call in rehearsal.register_selected_turn.call_args_list],
                         [SIDE1, SIDE2])
        checkpoints = rehearsal.recover_selection.call_args_list
        self.assertEqual([call.args[1].thread if call.args[1] else None for call in checkpoints],
                         [MAIN, None, SIDE1, SIDE2, MAIN, SIDE1, SIDE2, MAIN])
        self.assertTrue(rehearsal.side_lifecycle["old_codex_exited"])
        self.assertTrue(rehearsal.side_lifecycle["saved_threads_initially_unloaded"])
        calls = rehearsal.flow.mock_calls
        idle = next(index for index, call in enumerate(calls) if call[0] == "idle_resume_checkpoint")
        turns = [call.args[4] for call in calls[:idle] if call[0] == "register_selected_turn"]
        self.assertEqual(turns, ["CiaoSide1", "CiaoSide2"])
        self.assertEqual(calls[idle + 1][0], "recover_selection")
        self.assertFalse(any(call[0] == "register_selected_turn" for call in calls[idle + 1:]))
        rehearsal.warm_focus_cycle.assert_called_once()
        self.assertEqual(rehearsal.warm_focus_cycle.call_args.args[3:5],
                         (MAIN, {"CiaoSide1": SIDE1, "CiaoSide2": SIDE2}))

    def test_extended_flow_refuses_same_codex_incarnation_as_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            rehearsal = self.side_flow(directory, "old-incarnation")
            with patch.object(rehearse.subprocess, "run", return_value=Mock(returncode=1, stdout=b"")):
                with self.assertRaisesRegex(rehearse.Refused, "codex_tui_was_not_restarted"):
                    rehearsal.exercise_side_chats("old-session", "%10", 10)
        rehearsal.recover_selection.assert_not_called()

    def test_restored_thread_selection_never_reuses_old_checkpoint(self):
        rehearsal = object.__new__(rehearse.Rehearsal)
        rehearsal.backend = Mock(pid=1234)
        rehearsal.server_identity = SERVER
        rehearsal.kernel_identity = Mock(return_value=SERVER["identity"])
        rehearsal.status = Mock(side_effect=[snapshot(MAIN, 4), snapshot(SIDE1, 5)])
        def wait(_label, predicate):
            self.assertIsNone(predicate())
            return predicate()
        rehearsal.wait = wait
        self.assertEqual(rehearsal.selection(10, excluding={MAIN}, after=rehearse.Selection(MAIN, 2)),
                         rehearse.Selection(SIDE1, 5))

    def test_saved_chooser_navigates_actual_order_and_exact_owned_target(self):
        rehearsal = object.__new__(rehearse.Rehearsal)
        rehearsal.open_chooser = Mock(return_value="  ○ CiaoSide2\n› ○ CiaoSide1\n")
        rehearsal.screen = Mock(side_effect=["› + New side chat", "› ○ CiaoSide1"])
        rehearsal.keys = Mock()
        rehearsal.wait = lambda _label, predicate: self.assertTrue(predicate())
        rehearsal.choose_saved("owned", "%42", "CiaoSide1")
        self.assertEqual([call.args for call in rehearsal.keys.call_args_list],
                         [("owned", "%42", "Home"), ("owned", "%42", "Down"),
                          ("owned", "%42", "Down"), ("owned", "%42", "Enter")])

    def test_turn_needs_fresh_exact_route_reply_and_completed_hooks(self):
        rehearsal = object.__new__(rehearse.Rehearsal)
        rehearsal.backend = Mock(pid=1234)
        rehearsal.server_identity = SERVER
        rehearsal.mock = Mock(requests=3)
        rehearsal.status = Mock(return_value=snapshot(SIDE1, 4))
        rehearsal.command = Mock()
        rehearsal.session_for_thread = Mock(return_value="side-session")
        rehearsal.assistant_reply_count = Mock(side_effect=[1, 1, 2])
        fresh = (route("side-session", 10)
                 + "shared Codex terminal authenticated producer_pid=1234 terminal_pid=10 tail\n")
        rehearsal.daemon_log = Mock(side_effect=["old log", *["old log" + fresh] * 4])
        with tempfile.TemporaryDirectory() as directory:
            rehearsal.trace = Path(directory) / "trace"
            rehearsal.trace.write_text(" UserPromptSubmit ok\n Stop ok\n")
            def wait(_label, predicate, _seconds):
                self.assertFalse(predicate())  # Old hooks and reply cannot qualify.
                rehearsal.mock.requests = 4
                with rehearsal.trace.open("a") as stream:
                    stream.write(" UserPromptSubmit ok\n")
                self.assertFalse(predicate())  # Completion hook still missing.
                with rehearsal.trace.open("a") as stream:
                    stream.write(" Stop ok\n")
                self.assertFalse(predicate())  # An old persisted reply still cannot qualify.
                return predicate()
            rehearsal.wait = wait
            self.assertEqual(rehearsal.register_selected_turn(
                "owned", "%10", 10, rehearse.Selection(SIDE1, 2), "ResumedSide1"),
                rehearse.Selection(SIDE1, 4))
        self.assertTrue(all(call.args == (SIDE1,) for call in rehearsal.session_for_thread.call_args_list))

    def test_fresh_observer_check_logs_not_previous_daemon_log(self):
        rehearsal = object.__new__(rehearse.Rehearsal)
        rehearsal.mock = Mock(requests=6)
        rehearsal.daemon = Mock(pid=80)
        rehearsal.side_evidence = []
        rehearsal.ciao = Path("/owned/ciao")
        rehearsal.daemon_env = {"HOME": "/owned"}
        rehearsal.remaining = lambda seconds: seconds
        rehearsal.spawn = Mock(return_value=Mock())
        rehearsal.session_for_thread = Mock(return_value="side-session")
        rehearsal.rows = [{"session_id": "hidden-main", "pid": 10},
                          {"session_id": "baseline", "pid": 20},
                          {"session_id": "standalone", "pid": 30}]
        rehearsal.daemon_log = Mock(return_value=route("side-session", 10) + route("baseline", 20)
                                   + route("standalone", 30) + complete(3))
        selected = rehearse.Selection(SIDE1, 4)
        rehearsal.server_identity = SERVER
        rehearsal.status = Mock(return_value=snapshot(SIDE1, 4))
        rehearsal.wait = lambda _label, predicate, _seconds: self.assertTrue(predicate())
        with patch.object(rehearse.os, "killpg") as kill:
            rehearsal.recover_selection(10, selected, "focus-side1")
        kill.assert_called_once_with(80, rehearse.signal.SIGINT)
        self.assertEqual(rehearsal.spawn.call_args.args[1], "ciao-selection-0")
        self.assertEqual(rehearsal.side_evidence[0]["thread"], SIDE1)
        self.assertEqual(rehearsal.side_evidence[0]["session_id"], "side-session")

    def test_idle_checkpoint_requires_recovery_without_claiming_typed_route_use(self):
        with tempfile.TemporaryDirectory() as directory:
            r = object.__new__(rehearse.Rehearsal)
            r.trace = Path(directory) / "trace"
            r.trace.write_text("old hooks")
            r.mock = Mock(requests=5)
            r.rows = [{"session_id": "old-main", "pid": 10}, {"session_id": "baseline", "pid": 11}]
            r.side_lifecycle = {}
            r.cold_checkpoint = Mock()
            r.session_for_thread = Mock(return_value="old-main")
            r.idle_resume_checkpoint(20, rehearse.Selection(MAIN, 3))
            self.assertEqual(r.cold_checkpoint.call_args.args[-1], {("baseline", 11), ("old-main", 20)})
            self.assertFalse(r.side_lifecycle["idle_resume_routing"]["contract_exception"])
            self.assertEqual(r.side_lifecycle["idle_resume_routing"]["result"], "recovered_before_any_fresh_hook")
            self.assertEqual(r.side_lifecycle["idle_resume_routing"]["route_token_use"], "not_exercised")
            r.cold_checkpoint.side_effect = lambda *_args: r.trace.write_text("new hook")
            with self.assertRaisesRegex(rehearse.Refused, "idle_resume_checkpoint_generated_turn_or_hooks"):
                r.idle_resume_checkpoint(20, rehearse.Selection(MAIN, 3))

    def test_shared_recovery_completion_is_separate_from_startup_enumeration(self):
        expected = {("main", 20), ("standalone", 30)}
        log = route("standalone", 30) + complete(1)
        self.assertFalse(rehearse.completed_recovery(log, expected))
        log += "shared_recovered=1 Codex shared observation recovered\n"
        self.assertFalse(rehearse.completed_recovery(log, expected))
        self.assertTrue(rehearse.completed_recovery(log + route("main", 20), expected))
        with self.assertRaises(rehearse.Refused):
            rehearse.completed_recovery(log + route("unexpected", 40), expected)

    def warm_fixture(self, directory):
        r = object.__new__(rehearse.Rehearsal)
        r.trace = Path(directory) / "trace"
        r.trace.touch()
        r.mock = Mock(requests=5)
        r.daemon = Mock(pid=80)
        r.daemon.poll.return_value = None
        r.backend = Mock(pid=SERVER["pid"])
        r.kernel_identity = lambda pid: SERVER["identity"] if pid == SERVER["pid"] else "observer-incarnation"
        r.server_identity = SERVER
        r.side_evidence = []
        r.open_chooser, r.choose_saved, r.keys, r.selection = Mock(), Mock(), Mock(), Mock()
        r.wait = lambda _label, predicate: self.assertTrue(predicate())
        # Chooser is read once by wait and again for the receipted checkpoint.
        r.status = Mock(side_effect=[snapshot(MAIN, 4), snapshot(None, 5), snapshot(None, 5),
                                     snapshot(SIDE1, 6), snapshot(None, 7), snapshot(None, 7),
                                     snapshot(SIDE2, 8), snapshot(MAIN, 9)])
        r.spawn = Mock(side_effect=AssertionError("warm lane must never restart observer"))
        return r

    def test_warm_complete_focus_chooser_cycle_keeps_observer_without_turns(self):
        with tempfile.TemporaryDirectory() as directory:
            r = self.warm_fixture(directory)
            with patch.object(rehearse.os, "killpg", side_effect=AssertionError("no restart")):
                r.warm_focus_cycle("owned", "%20", 20, MAIN, {"CiaoSide1": SIDE1, "CiaoSide2": SIDE2},
                                   rehearse.Selection(SIDE2, 3))
        self.assertEqual([row["thread"] for row in r.side_evidence], [MAIN, None, SIDE1, None, SIDE2, MAIN])
        self.assertEqual([row["generation"] for row in r.side_evidence], list(range(4, 10)))
        self.assertEqual({row["observer_pid"] for row in r.side_evidence}, {80})
        for row in r.side_evidence:
            self.assertEqual(row["route_token_use"], "not_exercised")
            self.assertEqual(set(row["hidden_threads_not_displayed"]), {MAIN, SIDE1, SIDE2} - {row["thread"]})
        r.spawn.assert_not_called()

    def test_warm_lane_refuses_old_generation_wrong_selection_or_changed_observer(self):
        for bad in (snapshot(MAIN, 3), snapshot(SIDE1, 4), snapshot(MAIN, 4)):
            with tempfile.TemporaryDirectory() as directory:
                r = self.warm_fixture(directory)
                r.status = Mock(return_value=bad)
                if bad == snapshot(MAIN, 4):
                    r.daemon.poll.return_value = 1
                with self.assertRaises(rehearse.Refused):
                    r.warm_focus_cycle("owned", "%20", 20, MAIN, {"CiaoSide1": SIDE1, "CiaoSide2": SIDE2},
                                       rehearse.Selection(SIDE2, 3))
                self.assertFalse(r.side_evidence)

    def test_warm_return_to_same_uuid_cannot_revive_prior_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            r = self.warm_fixture(directory)
            values = list(r.status.side_effect)
            values[-1] = snapshot(MAIN, 4)  # Same UUID/revision as first main checkpoint (ABA).
            r.status.side_effect = values
            with self.assertRaisesRegex(rehearse.Refused, "warm_selection_not_fresh"):
                r.warm_focus_cycle("owned", "%20", 20, MAIN, {"CiaoSide1": SIDE1, "CiaoSide2": SIDE2},
                                   rehearse.Selection(SIDE2, 3))
            self.assertEqual(len(r.side_evidence), 5)

    def test_warm_lane_refuses_new_hooks_or_fixture_requests(self):
        for change in ("hook", "request"):
            with tempfile.TemporaryDirectory() as directory:
                r = self.warm_fixture(directory)
                def changed(*_args):
                    if change == "hook":
                        r.trace.write_text("new hook")
                    else:
                        r.mock.requests += 1
                r.selection.side_effect = changed
                with self.assertRaisesRegex(rehearse.Refused, "warm_observer_or_idle_fence_changed"):
                    r.warm_focus_cycle("owned", "%20", 20, MAIN, {"CiaoSide1": SIDE1, "CiaoSide2": SIDE2},
                                       rehearse.Selection(SIDE2, 3))

    def test_repeated_rollout_copy_of_old_answer_cannot_prove_a_new_turn(self):
        with tempfile.TemporaryDirectory() as directory:
            r = object.__new__(rehearse.Rehearsal)
            r.codex_home = Path(directory)
            sessions = r.codex_home / "sessions"
            sessions.mkdir()
            path = sessions / f"rollout-{SIDE1}.jsonl"
            def answer(number):
                return json.dumps({"type": "response_item", "payload": {"type": "message", "role": "assistant",
                    "content": [{"text": f"{rehearse.ANSWER}-{number}"}]}}) + "\n"
            path.write_text(answer(1))
            self.assertEqual(r.assistant_reply_count(SIDE1), 1)
            path.write_text(answer(1) * 2)
            self.assertEqual(r.assistant_reply_count(SIDE1), 1)
            path.write_text(answer(1) * 2 + answer(2))
            self.assertEqual(r.assistant_reply_count(SIDE1), 2)
            self.assertEqual(r.assistant_reply_count(MAIN), 0)

    @unittest.skipUnless(rehearse.sys.platform == "darwin" or rehearse.sys.platform.startswith("linux"),
                         "kernel incarnation contract is macOS/Linux")
    def test_native_kernel_identity_of_this_test_process_is_stable(self):
        rehearsal = object.__new__(rehearse.Rehearsal)
        first = rehearsal.kernel_identity(rehearse.os.getpid())
        second = rehearsal.kernel_identity(rehearse.os.getpid())
        self.assertEqual(first, second)
        self.assertRegex(first, r"^(macos|linux):[0-9a-f-]{36}:[1-9][0-9]*$")

    @unittest.skipUnless(rehearse.sys.platform == "darwin", "extended network fence is macOS-only")
    def test_local_network_policy_compiles_without_a_vendor_or_network_request(self):
        result = subprocess.run(["/usr/bin/sandbox-exec", "-p", rehearse.LOCAL_NETWORK_POLICY,
                                 "/usr/bin/true"], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    @unittest.skipUnless(rehearse.sys.platform == "darwin" or rehearse.sys.platform.startswith("linux"),
                         "Unix peer credential contract is macOS/Linux")
    def test_native_unix_peer_credentials_of_this_test_process(self):
        rehearsal = object.__new__(rehearse.Rehearsal)
        left, right = rehearse.socket.socketpair()
        with left, right:
            rehearsal.authenticate_peer(left, rehearse.os.getpid())
            with self.assertRaises(rehearse.Refused):
                rehearsal.authenticate_peer(left, rehearse.os.getpid() + 1)

    def test_peer_pid_or_uid_mismatch_is_refused(self):
        rehearsal = object.__new__(rehearse.Rehearsal)
        with patch.object(rehearse.sys, "platform", "linux"):
            for pid, uid in ((20, rehearse.os.getuid()), (10, rehearse.os.getuid() + 1)):
                peer = Mock()
                peer.getsockopt.return_value = rehearse.struct.pack("3i", pid, uid, 0)
                # SO_PEERCRED is not exported by macOS Python, even for this fake peer.
                with patch.object(rehearse.socket, "SO_PEERCRED", 17, create=True):
                    with self.assertRaises(rehearse.Refused):
                        rehearsal.authenticate_peer(peer, 10)


if __name__ == "__main__":
    unittest.main()
