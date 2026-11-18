"""Public, local-only builder regressions; no compiler, network or Codex turn is run."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("build_vendor.py")


class BuildVendorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ciao-vendor-builder-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.checkout = self.root / "public"
        self.checkout.mkdir()
        self.git("init")
        (self.checkout / "codex-rs").mkdir()
        (self.checkout / "codex-rs/source.rs").write_text("baseline\n")
        (self.checkout / "codex-rs/other.rs").write_text("grounded\n")
        (self.checkout / "codex-rs/link.rs").symlink_to("other.rs")
        (self.checkout / ".gitignore").write_text("/codex-rs/target/\n")
        (self.checkout / "LICENSE").write_text("public fixture license\n")
        (self.checkout / "NOTICE").write_text("public fixture notice\n")
        self.git("add", ".gitignore", "LICENSE", "NOTICE", "codex-rs/source.rs", "codex-rs/other.rs", "codex-rs/link.rs")
        self.git("commit", "-m", "public fixture")
        self.base = self.git("rev-parse", "HEAD").strip()
        (self.checkout / "codex-rs/source.rs").write_text("reviewed patch\n")
        (self.checkout / "codex-rs/new.rs").write_text("reviewed new source\n")
        self.git("add", "codex-rs/source.rs", "codex-rs/new.rs")
        self.patch = self.root / "reviewed.patch"
        self.patch.write_text(self.git("diff", "--cached", "--binary"))
        self.git("reset", "--hard", self.base)
        spec = importlib.util.spec_from_file_location("candidate_builder_fixture", SCRIPT)
        self.builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.builder)
        self.builder.BASE_COMMIT = self.base
        self.builder.PATCH = self.patch

    def git(self, *arguments):
        environment = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
        environment.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"})
        result = subprocess.run(
            ["git", "-c", "user.name=Public fixture", "-c", "user.email=fixture@example.invalid", *arguments],
            cwd=self.checkout, env=environment, check=True, capture_output=True,
        )
        return result.stdout.decode()

    def args(self, **overrides):
        values = dict(checkout=self.checkout, out=self.root / "candidate", cargo_home=self.root / "vendor-cache", jobs=2, profile="dev-small", check=False)
        values.update(overrides)
        return argparse.Namespace(**values)

    def fake_compiler(self, mutation=None):
        real_checked = self.builder.checked
        calls = []

        def checked(argv, **kwargs):
            if argv[:2] == ["rustc", "--version"]:
                return "rustc fixture"
            if argv[:2] == ["cargo", "--version"]:
                return "cargo fixture"
            if argv[:2] == ["cargo", "build"]:
                target = Path(kwargs["env"]["CARGO_TARGET_DIR"])
                self.assertNotEqual(target, self.checkout / "codex-rs/target")
                self.assertNotIn(self.checkout, target.parents)
                self.assertIn("--locked", argv)
                self.assertEqual(argv[-2:], ["-j", "2"])
                self.assertFalse((target / "dev-small/codex").exists())
                calls.append(target)
                if mutation:
                    mutation()
                binary = target / "dev-small/codex"
                binary.parent.mkdir()
                binary.write_bytes(b"fresh public compiler fixture\n")
                return ""
            if argv[-1:] == ["--version"]:
                return f"codex-cli {self.builder.BASE_VERSION}"
            return real_checked(argv, **kwargs)

        return checked, calls

    def test_clean_tree_and_reviewed_patch_create_bound_unofficial_artifacts(self):
        stale = self.root / "test-only-old-target/dev-small/codex"
        stale.parent.mkdir(parents=True)
        stale.write_bytes(b"unbound old binary")
        self.assertEqual(self.git("status", "--porcelain").strip(), "")
        compiler, calls = self.fake_compiler()
        with mock.patch.object(self.builder, "checked", compiler):
            manifest = self.builder.build(self.args())
        output = self.root / "candidate"
        self.assertEqual((output / "codex").read_bytes(), b"fresh public compiler fixture\n")
        self.assertEqual(stale.read_bytes(), b"unbound old binary")
        self.assertEqual(set(path.name for path in output.iterdir()), {"codex", "provenance.json", "LICENSE", "NOTICE"})
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.args().cargo_home.stat().st_mode & 0o777, 0o700)
        self.assertFalse(calls[0].exists())
        self.assertFalse(manifest["official_binary"])
        self.assertFalse(manifest["installed"])
        self.assertEqual(manifest["cargo_home_policy"], "new-private-home-no-reused-dependency-sources")
        self.assertEqual(manifest["source_commit"], self.base)
        self.assertEqual(manifest["binary_sha256"], hashlib.sha256((output / "codex").read_bytes()).hexdigest())
        self.assertEqual(json.loads((output / "provenance.json").read_text()), manifest)
        for name in ("LICENSE", "NOTICE"):
            source = self.checkout / name
            copied = output / name
            self.assertEqual(copied.read_bytes(), source.read_bytes())
            self.assertEqual(manifest[f"{name.lower()}_sha256"], hashlib.sha256(copied.read_bytes()).hexdigest())
            self.assertNotEqual((source.stat().st_dev, source.stat().st_ino), (copied.stat().st_dev, copied.stat().st_ino))
        binding = self.builder.source_binding(self.checkout)
        self.assertIn("codex-rs/other.rs", binding)
        self.assertIn("codex-rs/new.rs", binding)
        self.assertEqual(binding["codex-rs/link.rs"]["mode"], "120000")

    def assert_reused_home_refused(self, contents=None):
        home = self.root / "reused-home"
        home.mkdir(mode=0o700)
        if contents:
            file = home / contents
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text("tampered cached input\n")
        compiler, calls = self.fake_compiler()
        with mock.patch.object(self.builder, "checked", compiler):
            with self.assertRaises(self.builder.Refused):
                self.builder.build(self.args(cargo_home=home))
        self.assertEqual(calls, [])
        self.assertFalse((self.root / "candidate").exists())
        self.assertEqual((self.checkout / "codex-rs/source.rs").read_text(), "baseline\n")

    def test_reused_empty_cargo_home_is_refused(self):
        self.assert_reused_home_refused()

    def test_reused_tampered_git_dependency_home_is_refused(self):
        self.assert_reused_home_refused("git/checkouts/dep/rev/src/lib.rs")

    def test_reused_tampered_registry_dependency_home_is_refused(self):
        self.assert_reused_home_refused("registry/src/index/dep/src/lib.rs")

    def test_reused_legacy_config_home_is_refused(self):
        self.assert_reused_home_refused("config")

    def assert_home_symlink_refused(self, exists):
        target = self.root / "home-target"
        if exists:
            target.mkdir()
        link = self.root / "home-link"
        link.symlink_to(target, target_is_directory=True)
        compiler, calls = self.fake_compiler()
        with mock.patch.object(self.builder, "checked", compiler):
            with self.assertRaises(self.builder.Refused):
                self.builder.build(self.args(cargo_home=link))
        self.assertEqual(calls, [])
        self.assertEqual(target.exists(), exists)
        self.assertFalse((self.root / "candidate").exists())

    def test_existing_cargo_home_symlink_is_refused(self):
        self.assert_home_symlink_refused(True)

    def test_dangling_cargo_home_symlink_is_refused(self):
        self.assert_home_symlink_refused(False)

    def test_check_does_not_create_cargo_home_output_or_patch_sources(self):
        args = self.args(check=True)
        result = self.builder.build(args)
        self.assertTrue(result["applicable"])
        self.assertFalse(args.cargo_home.exists())
        self.assertFalse(args.out.exists())
        self.assertEqual((self.checkout / "codex-rs/source.rs").read_text(), "baseline\n")

    def test_cargo_home_reservation_refuses_a_racing_directory(self):
        args = self.args()
        validate = self.builder.validate_source
        def raced(checkout):
            validate(checkout)
            args.cargo_home.mkdir()
            (args.cargo_home / "untrusted").write_text("racing cache\n")
        compiler, calls = self.fake_compiler()
        with mock.patch.object(self.builder, "validate_source", raced), mock.patch.object(self.builder, "checked", compiler):
            with self.assertRaises((self.builder.Refused, FileExistsError)):
                self.builder.build(args)
        self.assertEqual(calls, [])
        self.assertEqual((self.checkout / "codex-rs/source.rs").read_text(), "baseline\n")
        self.assertFalse((args.out / "provenance.json").exists())

    def test_ignored_legacy_config_is_refused_before_and_after_patch(self):
        config = self.checkout / "codex-rs/.cargo/config"
        config.parent.mkdir()
        (self.checkout / ".git/info/exclude").write_text("codex-rs/.cargo/config\n")
        config.write_text('[build]\nrustflags = ["--cfg", "unbound"]\n')
        self.assertEqual(self.git("status", "--porcelain"), "")
        with self.assertRaisesRegex(self.builder.Refused, "ignored inputs"):
            self.builder.validate_source(self.checkout)
        self.git("apply", str(self.patch))
        with self.assertRaisesRegex(self.builder.Refused, "ignored inputs"):
            self.builder.source_binding(self.checkout)

    def test_ancestor_configs_including_legacy_are_refused(self):
        directory = self.root / ".cargo"
        directory.mkdir()
        for name in ("config", "config.toml"):
            with self.subTest(name=name):
                config = directory / name
                config.write_text('[build]\nrustflags = []\n')
                with self.assertRaisesRegex(self.builder.Refused, "ancestor Cargo"):
                    self.builder.validate_source(self.checkout)
                config.unlink()
        self.builder.validate_source(self.checkout)

    def test_external_symlink_input_is_refused_even_when_tracked(self):
        external = self.root / "external.rs"
        external.write_text("external input\n")
        link = self.checkout / "codex-rs/link.rs"
        link.unlink()
        link.symlink_to(external)
        self.git("add", "codex-rs/link.rs")
        self.git("commit", "-m", "external symlink fixture")
        self.builder.BASE_COMMIT = self.git("rev-parse", "HEAD").strip()
        with self.assertRaisesRegex(self.builder.Refused, "external symlink"):
            self.builder.validate_source(self.checkout)

    def test_config_injected_during_compile_refuses_artifacts(self):
        for index, location in enumerate(("source", "ancestor", "cargo-home")):
            with self.subTest(location=location):
                args = self.args(out=self.root / f"config-candidate-{index}",
                                 cargo_home=self.root / f"config-cargo-{index}")
                config = {"source": self.checkout / "codex-rs/.cargo/config",
                          "ancestor": self.root / ".cargo/config.toml",
                          "cargo-home": args.cargo_home / "config"}[location]
                def mutate():
                    config.parent.mkdir(parents=True, exist_ok=True)
                    config.write_text("[build]\nrustflags = []\n")
                    (self.checkout / ".git/info/exclude").write_text("codex-rs/.cargo/config\n")
                compiler, _ = self.fake_compiler(mutate)
                with mock.patch.object(self.builder, "checked", compiler):
                    with self.assertRaises(self.builder.Refused):
                        self.builder.build(args)
                self.assertFalse((args.out / "codex").exists())
                self.assertFalse((args.out / "provenance.json").exists())
                config.unlink()
                self.git("reset", "--hard", self.base)
                (self.checkout / "codex-rs/new.rs").unlink()

    def test_wrong_numeric_version_refuses_candidate(self):
        compiler, _ = self.fake_compiler()
        def wrong_version(argv, **kwargs):
            if argv[-1:] == ["--version"] and Path(argv[0]).name == "codex":
                return "codex-cli 0.166.0"
            return compiler(argv, **kwargs)
        with mock.patch.object(self.builder, "checked", wrong_version):
            with self.assertRaisesRegex(self.builder.Refused, "grounded base version"):
                self.builder.build(self.args())
        self.assertFalse((self.root / "candidate/codex").exists())
        self.assertFalse((self.root / "candidate/provenance.json").exists())

    def test_public_base_is_exact_0169_not_a_moving_tag(self):
        self.assertEqual(self.builder.BASE_VERSION, "0.169.0")
        spec = importlib.util.spec_from_file_location("candidate_public_pin", SCRIPT)
        public = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(public)
        self.assertEqual(public.BASE_COMMIT, "d32063f96c2dff1dc96af839b3952abb6acfeda4")
        self.assertEqual(public.PATCH.name, "codex-0.169.0.patch")

    def test_hidden_tracked_changes_refuse_assume_unchanged_skip_worktree_and_fsmonitor(self):
        file = self.checkout / "codex-rs/other.rs"
        for flag in ("--assume-unchanged", "--skip-worktree", "--fsmonitor-valid"):
            with self.subTest(flag=flag):
                self.git("update-index", flag, "codex-rs/other.rs")
                file.write_text("unreviewed compiler input\n")
                if flag != "--fsmonitor-valid":
                    self.assertEqual(self.git("status", "--porcelain").strip(), "", "precondition: porcelain hides this change")
                with self.assertRaisesRegex(self.builder.Refused, "grounded public tree"):
                    self.builder.validate_source(self.checkout)
                file.write_text("grounded\n")
                self.git("update-index", "--no-assume-unchanged", "--no-skip-worktree", "--no-fsmonitor-valid", "codex-rs/other.rs")
                self.builder.validate_source(self.checkout)

    def test_symlink_targets_are_bound_without_following_them(self):
        self.builder.validate_source(self.checkout)
        link = self.checkout / "codex-rs/link.rs"
        self.git("update-index", "--assume-unchanged", "codex-rs/link.rs")
        link.unlink()
        link.symlink_to("source.rs")
        self.assertEqual(self.git("status", "--porcelain").strip(), "")
        with self.assertRaisesRegex(self.builder.Refused, "grounded public tree"):
            self.builder.validate_source(self.checkout)

    def test_replacement_objects_are_refused_even_when_head_and_status_look_grounded(self):
        (self.checkout / "codex-rs/other.rs").write_text("replacement compiler input\n")
        self.git("add", "codex-rs/other.rs")
        self.git("commit", "-m", "replacement fixture")
        replacement = self.git("rev-parse", "HEAD").strip()
        self.git("replace", self.base, replacement)
        self.git("reset", "--hard", self.base)
        self.assertEqual(self.git("rev-parse", "HEAD").strip(), self.base)
        self.assertEqual(self.git("status", "--porcelain").strip(), "")
        with self.assertRaisesRegex(self.builder.Refused, "replacement objects"):
            self.builder.validate_source(self.checkout)

    def test_inherited_git_directory_and_config_overrides_do_not_redirect_inspection(self):
        with mock.patch.dict(os.environ, {"GIT_DIR": str(self.root / "not-a-repository"), "GIT_WORK_TREE": str(self.root), "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.bare", "GIT_CONFIG_VALUE_0": "true"}):
            self.builder.validate_source(self.checkout)

    def test_source_inspection_does_not_execute_repository_fsmonitor_hooks(self):
        marker = self.root / "fsmonitor-was-executed"
        hook = self.root / "fsmonitor-hook"
        hook.write_text("#!/bin/sh\nprintf x > " + shlex.quote(str(marker)) + "\nprintf '\\0'\n")
        hook.chmod(0o755)
        self.git("config", "core.fsmonitor", str(hook))
        self.git("status", "--porcelain")
        self.assertTrue(marker.exists(), "precondition: ordinary Git status executes this hook")
        marker.unlink()
        self.builder.validate_source(self.checkout)
        self.assertFalse(marker.exists(), "the builder must not execute unreviewed Git helpers")

    def test_existing_outputs_dangling_symlinks_and_global_cache_are_refused_before_patch(self):
        existing = self.root / "existing-bin"
        existing.mkdir()
        dangling = self.root / "dangling-output"
        dangling.symlink_to(self.root / "not-created")
        for args in (self.args(out=existing), self.args(out=dangling), self.args(cargo_home=Path.home() / ".cargo")):
            with self.subTest(output=args.out):
                with self.assertRaises(self.builder.Refused):
                    self.builder.build(args)
                self.assertEqual((self.checkout / "codex-rs/source.rs").read_text(), "baseline\n")
                self.assertFalse((self.checkout / "codex-rs/new.rs").exists())
        self.assertFalse((self.root / "not-created").exists())

    def test_global_cache_identity_is_not_changed_by_filesystem_aliases(self):
        global_cache = self.root / "global-cache"
        global_cache.mkdir()
        alias = self.root / "cache-alias"
        alias.symlink_to(global_cache, target_is_directory=True)
        candidates = [alias]
        case_alias = self.root / "GLOBAL-CACHE"
        if case_alias.exists():
            self.assertTrue(case_alias.samefile(global_cache))
            candidates.append(case_alias)
        with mock.patch.dict(os.environ, {"CARGO_HOME": str(global_cache)}):
            for candidate in candidates:
                with self.subTest(candidate=candidate):
                    with self.assertRaisesRegex(self.builder.Refused, "dedicated cache"):
                        self.builder.build(self.args(cargo_home=candidate))
        self.assertEqual((self.checkout / "codex-rs/source.rs").read_text(), "baseline\n")

    def test_compiler_input_changes_during_build_refuse_artifacts(self):
        for index, path in enumerate(("codex-rs/other.rs", "codex-rs/new.rs")):
            with self.subTest(path=path):
                def mutate():
                    if path.endswith("other.rs"):
                        self.git("update-index", "--assume-unchanged", path)
                    (self.checkout / path).write_text("changed while building\n")
                compiler, _ = self.fake_compiler(mutate)
                output = self.root / f"candidate-{index}"
                with mock.patch.object(self.builder, "checked", compiler):
                    with self.assertRaises(self.builder.Refused):
                        self.builder.build(self.args(out=output, cargo_home=self.root / f"mutation-cargo-{index}"))
                self.assertFalse((output / "codex").exists())
                self.assertFalse((output / "provenance.json").exists())
                self.git("update-index", "--no-assume-unchanged", "codex-rs/other.rs")
                self.git("reset", "--hard", self.base)
                (self.checkout / "codex-rs/new.rs").unlink()

    @unittest.skipUnless(os.name == "posix", "private process groups require POSIX")
    def test_timeout_stops_the_build_child_process_group(self):
        ready = self.root / "ready"
        stopped = self.root / "stopped"
        child = "import signal,sys,time;from pathlib import Path;signal.signal(signal.SIGTERM,lambda *_:(Path(sys.argv[2]).write_text('stopped'),sys.exit(0)));Path(sys.argv[1]).write_text('ready');time.sleep(10)"
        parent = "import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2],sys.argv[3]]);time.sleep(10)"
        with self.assertRaisesRegex(self.builder.Refused, "timed out"):
            self.builder.checked([sys.executable, "-c", parent, child, str(ready), str(stopped)], cwd=self.root, timeout=1)
        self.assertTrue(ready.exists(), "precondition: the descendant armed its termination handler")
        self.assertEqual(stopped.read_text(), "stopped", "the descendant, not just the Cargo parent, was terminated")


if __name__ == "__main__":
    unittest.main()
