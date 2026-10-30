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
                return "codex-cli 0.166.0"
            return real_checked(argv, **kwargs)

        return checked, calls

    def test_clean_tree_and_reviewed_patch_create_bound_unofficial_artifacts(self):
        stale = self.checkout / "codex-rs/target/dev-small/codex"
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
        self.assertFalse(calls[0].exists())
        self.assertFalse(manifest["official_binary"])
        self.assertFalse(manifest["installed"])
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
                        self.builder.build(self.args(out=output))
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
