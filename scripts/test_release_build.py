"""release_build.py against a fake cargo and git: the record exists only on green, the archive is
deterministic and refuses a cross build or a missing token, and the manifest binds every file in
dist/ to the head or refuses by name. No network, no real cargo, and the machine's own platform is
never consulted: the target is stated by each test."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_build as rb  # noqa: E402

HEAD, OTHER = "a" * 40, "b" * 40
DARWIN, LINUX = "aarch64-apple-darwin", "x86_64-unknown-linux-gnu"
GREEN = b"running 3 tests\ntest result: ok. 3 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out\n"
RED = b"running 3 tests\ntest result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n"


class FakeRunner:
    """argv in, scripted (exit, output) out; a `cargo build` writes the binary it is asked for."""

    def __init__(self, root, *, dirty=False, tests=GREEN, fail=None, binary=b"\x7fELF fixture binary"):
        self.root, self.dirty, self.tests, self.fail, self.binary, self.calls = Path(root), dirty, tests, fail, binary, []

    def __call__(self, argv, *, cwd=None, timeout, env=None):
        self.calls.append({"argv": list(argv), "env": env})
        if argv[:1] == ["git"] and argv[3:] == ["rev-parse", "HEAD"]:
            return 0, (HEAD + "\n").encode()
        if argv[:1] == ["git"] and argv[3] == "status":
            return 0, b" M crates/ciao-host/src/lib.rs\n" if self.dirty else b""
        if argv == ["cargo", "--version"]:
            return 0, b"cargo 1.98.1 (0123456789 2026-01-01)\n"
        if argv[:2] == ["cargo", "build"]:
            if self.fail == "build":
                return 101, b"error: fixture build failure\n"
            target = argv[argv.index("--target") + 1]
            binary = self.root / "target" / target / "release" / "ciao"
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(self.binary)
            return 0, b""
        if argv[:1] == ["cargo"] and argv[1] in ("fmt", "clippy", "test"):
            if self.fail == argv[1]:
                return 101, b"error: fixture " + argv[1].encode() + b" failure\n"
            return 0, self.tests if argv[1] == "test" else b""
        raise AssertionError("unexpected command " + " ".join(argv))

    def names(self):
        return [" ".join(c["argv"][:2]) for c in self.calls]


def fixture_root(root, version="0.1.2"):
    root = Path(root)
    (root / "crates/ciao-host").mkdir(parents=True)
    (root / "crates/ciao-host/Cargo.toml").write_text(f'[package]\nname = "ciao-host"\nversion = "{version}"\nedition = "2024"\n')
    for name in rb.TEXT_FILES:
        (root / name).write_text(f"{name} text\n")
    return root


class NativeRecordTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = fixture_root(Path(self.tmp.name).resolve() / "host")
        patcher = patch.object(rb, "detected_host_target", return_value=LINUX)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.out = self.root.parent / "dist/native-linux-x64.json"

    def test_the_record_is_written_only_when_all_three_checks_are_green(self):
        runner = FakeRunner(self.root)
        record = rb.native_record(runner, self.root, self.out, emit=lambda _line: None)
        self.assertEqual((record["head"], record["platform"], record["toolchain"], record["checks"]),
                         (HEAD, "linux-x64", "1.98.1", {"fmt": 0, "clippy": 0, "host_tests": 3}))
        self.assertEqual(record["runner"], "scripts/release_build.py")
        self.assertEqual(record["runner_sha256"], hashlib.sha256(Path(rb.__file__).read_bytes()).hexdigest())
        self.assertEqual(json.loads(self.out.read_text()), record)
        cargo = [c["argv"] for c in runner.calls if c["argv"][0] == "cargo"]
        self.assertEqual([c[1] for c in cargo], ["--version", "fmt", "clippy", "test"])
        self.assertIn("--test-threads=1", cargo[-1], "serial, so the last test line names a hang")
        for fail, category in (("test", "host_tests_failed"), ("clippy", "clippy_failed"), ("fmt", "fmt_failed")):
            with self.subTest(fail=fail):
                self.out.unlink(missing_ok=True)
                with self.assertRaisesRegex(rb.Refused, category):
                    rb.native_record(FakeRunner(self.root, fail=fail), self.root, self.out, emit=lambda _line: None)
                self.assertFalse(self.out.exists(), "a red run must leave no record behind")
        self.assertFalse(self.out.exists())
        with self.assertRaisesRegex(rb.Refused, "host_tests_failed"):
            rb.native_record(FakeRunner(self.root, tests=RED), self.root, self.out, emit=lambda _line: None)
        with self.assertRaisesRegex(rb.Refused, "host_tests_failed"):
            rb.native_record(FakeRunner(self.root, tests=b"no summary line\n"), self.root, self.out, emit=lambda _line: None)
        self.assertFalse(self.out.exists())

    def test_a_dirty_tree_or_an_unknown_host_refuses_before_cargo_runs(self):
        runner = FakeRunner(self.root, dirty=True)
        with self.assertRaisesRegex(rb.Refused, "source_not_clean"):
            rb.native_record(runner, self.root, self.out, emit=lambda _line: None)
        self.assertNotIn("cargo fmt", runner.names())
        with patch.object(rb, "detected_host_target", return_value=""):
            with self.assertRaisesRegex(rb.Refused, "unsupported_build_host"):
                rb.native_record(FakeRunner(self.root), self.root, self.out, emit=lambda _line: None)


class PackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = fixture_root(Path(self.tmp.name).resolve() / "host")
        self.dist = self.root.parent / "dist"
        patcher = patch.object(rb, "detected_host_target", return_value=DARWIN)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_pack_builds_this_targets_release_and_writes_a_deterministic_archive_with_its_sidecar(self):
        runner = FakeRunner(self.root)
        result = rb.pack(runner, self.root, self.dist, {"PATH": "/usr/bin", "CIAO_RELAY_TOKEN": "fixture-token"}, emit=lambda _line: None)
        name = f"ciao-0.1.2-{DARWIN}.tar"
        archive = (self.dist / name).read_bytes()
        self.assertEqual(result, {"file": name, "target": DARWIN, "version": "0.1.2",
                                  "sha256": hashlib.sha256(archive).hexdigest(), "bytes": len(archive)})
        self.assertEqual((self.dist / f"{name}.sha256").read_text(), f"{result['sha256']}  {name}\n")
        build = next(c for c in runner.calls if c["argv"][:2] == ["cargo", "build"])
        self.assertEqual(build["argv"], ["cargo", "build", "--locked", "--release", "--target", DARWIN])
        self.assertEqual(build["env"]["CIAO_RELAY_TOKEN"], "fixture-token", "the token reaches cargo through the environment only")
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
            members = tar.getmembers()
            self.assertEqual([m.name for m in members], ["ciao", *rb.TEXT_FILES, "install.json"])
            self.assertEqual([m.mode for m in members], [0o755, 0o644, 0o644, 0o644, 0o644])
            self.assertTrue(all(m.mtime == 0 and m.uid == 0 and m.gid == 0 and m.uname == "" for m in members))
            self.assertEqual(tar.extractfile("ciao").read(), b"\x7fELF fixture binary")
            self.assertEqual(json.loads(tar.extractfile("install.json").read()), {"v": 1, "version": "0.1.2", "target": DARWIN})
        again = rb.pack(FakeRunner(self.root), self.root, self.root.parent / "again", {"CIAO_RELAY_TOKEN": "fixture-token"}, emit=lambda _line: None)
        self.assertEqual(again["sha256"], result["sha256"], "equal inputs pack to identical bytes")

    def test_the_archive_writer_is_pinned_byte_for_byte(self):
        # The private repository's publisher reads these archives with its own checker; a change in
        # the writer's bytes is a contract change both sides must see, so the golden digest is here.
        members = [("ciao", b"#!/bin/sh\necho fixture\n", 0o755), ("LICENSE-MIT", b"MIT\n", 0o644),
                   ("LICENSE-APACHE", b"Apache\n", 0o644), ("THIRD-PARTY-NOTICES.md", b"notices\n", 0o644),
                   ("install.json", b'{"v": 1, "version": "9.9.9", "target": "x86_64-unknown-linux-gnu"}\n', 0o644)]
        # Measured 2026-09-19 from this writer and from the private repository's `package_host.deterministic_tar`,
        # which produced the same bytes: the two repositories pack one archive format.
        self.assertEqual(hashlib.sha256(rb.deterministic_tar(members)).hexdigest(),
                         "6b5b29fab65f6ff20fe50359c4d1c85cf908e03892305712d77646415a22b6c6")
        self.assertEqual(len(rb.deterministic_tar(members)), 10240, "five small members padded to one 10240-byte record")

    def test_no_token_or_a_foreign_target_refuses_before_any_build(self):
        runner = FakeRunner(self.root)
        for environ in ({}, {"CIAO_RELAY_TOKEN": ""}, {"CIAO_RELAY_TOKEN": "   "}):
            with self.subTest(environ=environ), self.assertRaisesRegex(rb.Refused, "relay_token_required"):
                rb.pack(runner, self.root, self.dist, environ, emit=lambda _line: None)
        self.assertNotIn("cargo build", runner.names())
        self.assertFalse(self.dist.exists())
        with self.assertRaisesRegex(rb.Refused, "cross_build_refused"):
            rb.build_binary(runner, self.root, LINUX, {"CIAO_RELAY_TOKEN": "fixture-token"})
        self.assertNotIn("cargo build", runner.names())
        with self.assertRaisesRegex(rb.Refused, "release_build_failed"):
            rb.build_binary(FakeRunner(self.root, fail="build"), self.root, DARWIN, {"CIAO_RELAY_TOKEN": "fixture-token"})
        stale = self.root / "target" / DARWIN / "release" / "ciao"
        stale.parent.mkdir(parents=True)
        stale.write_bytes(b"previous run")
        with self.assertRaisesRegex(rb.Refused, "release_build_failed"):
            rb.build_binary(FakeRunner(self.root, fail="build"), self.root, DARWIN, {"CIAO_RELAY_TOKEN": "fixture-token"})
        self.assertFalse(stale.exists(), "a failed build cannot ship the previous binary")


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = fixture_root(Path(self.tmp.name).resolve() / "host")
        self.dist = self.root.parent / "dist"
        self.dist.mkdir()
        for target in sorted(rb.RELEASE_TARGETS):
            archive = rb.deterministic_tar(rb.archive_members(b"binary for " + target.encode(), "0.1.2", target, self.root))
            name = f"ciao-0.1.2-{target}.tar"
            (self.dist / name).write_bytes(archive)
            (self.dist / f"{name}.sha256").write_text(f"{hashlib.sha256(archive).hexdigest()}  {name}\n")
            with patch.object(rb, "detected_host_target", return_value=target):
                rb.native_record(FakeRunner(self.root), self.root, self.dist / f"native-{rb.PLATFORMS[target]}.json", emit=lambda _line: None)

    def manifest(self, **kwargs):
        return rb.manifest(FakeRunner(self.root), self.root, self.dist, emit=lambda _line: None, **kwargs)

    def test_the_manifest_binds_every_file_to_the_head_and_writes_the_check_run_body(self):
        record = self.manifest(run_url="https://github.com/bojanstef/ciao-host/actions/runs/1", run_id="35477571308")
        release = json.loads((self.dist / "release.json").read_text())
        self.assertEqual([a["target"] for a in release["artifacts"]], sorted(rb.RELEASE_TARGETS))
        self.assertEqual(release["v"], 1)
        for artifact in release["artifacts"]:
            self.assertEqual(artifact["sha256"], hashlib.sha256((self.dist / artifact["file"]).read_bytes()).hexdigest())
            self.assertEqual(artifact["bytes"], (self.dist / artifact["file"]).stat().st_size)
        self.assertEqual(set(record["files"]), {p.name for p in self.dist.iterdir()} - {"check-run.json"})
        for name, digest in record["files"].items():
            self.assertEqual(digest, hashlib.sha256((self.dist / name).read_bytes()).hexdigest(), name)
        self.assertEqual((record["head"], record["version"], set(record["platforms"])), (HEAD, "0.1.2", {"darwin-arm64", "linux-x64"}))
        self.assertEqual(record["platforms"]["linux-x64"]["checks"]["host_tests"], 3)
        body = json.loads((self.dist / "check-run.json").read_text())
        self.assertEqual((body["name"], body["head_sha"], body["status"], body["conclusion"]),
                         ("release-artifacts", HEAD, "completed", "success"))
        self.assertEqual(body["details_url"], "https://github.com/bojanstef/ciao-host/actions/runs/1")
        self.assertEqual(body["external_id"], "35477571308", "the one field GitHub leaves alone; it names the run whose artifacts these are")
        with self.assertRaisesRegex(rb.Refused, "run_id_invalid"):
            self.manifest(run_id="not-a-run")
        self.assertEqual(json.loads(body["output"]["summary"]), record, "the summary IS the record, canonical")
        self.assertIn("0.1.2", body["output"]["title"])

    def test_the_manifest_refuses_by_name_and_writes_nothing_then(self):
        cases = []
        linux = f"ciao-0.1.2-{LINUX}.tar"
        cases.append(("artifact_missing: linux-x64", lambda: (self.dist / linux).unlink()))
        cases.append(("archive_sidecar_mismatch", lambda: (self.dist / f"{linux}.sha256").write_text(f"{'0' * 64}  {linux}\n")))
        cases.append(("native_record_missing: linux-x64", lambda: (self.dist / "native-linux-x64.json").unlink()))
        cases.append(("native_record_invalid", lambda: (self.dist / "native-linux-x64.json").write_text(
            (self.dist / "native-linux-x64.json").read_text().replace(HEAD, OTHER))))
        cases.append(("unexpected_files_in_dist", lambda: (self.dist / "native-linux-x64-fmt.log").write_text("log\n")))
        cases.append(("invalid_release_archive", lambda: (self.root / "LICENSE-MIT").write_text("changed after packing\n")))
        for category, mutate in cases:
            with self.subTest(category=category):
                saved = {p.name: p.read_bytes() for p in self.dist.iterdir()}
                license_text = (self.root / "LICENSE-MIT").read_bytes()
                mutate()
                with self.assertRaisesRegex(rb.Refused, category):
                    self.manifest()
                self.assertFalse((self.dist / "check-run.json").exists())
                for path in list(self.dist.iterdir()):
                    path.unlink()
                for name, data in saved.items():
                    (self.dist / name).write_bytes(data)
                (self.root / "LICENSE-MIT").write_bytes(license_text)
        (self.root / "crates/ciao-host/Cargo.toml").write_text('[package]\nname = "ciao-host"\nversion = "0.1.3"\n')
        with self.assertRaisesRegex(rb.Refused, "artifact_missing"):
            self.manifest()

    def test_the_cli_exits_two_with_one_error_line_on_a_refusal(self):
        (self.dist / f"ciao-0.1.2-{LINUX}.tar").unlink()
        err = io.StringIO()
        with patch("sys.stderr", err), patch("sys.stdout", io.StringIO()):
            code = rb.main(["--root", str(self.root), "manifest", "--dist", str(self.dist)], runner=FakeRunner(self.root))
        self.assertEqual(code, 2)
        self.assertEqual(err.getvalue().strip(), "::error::release_build: artifact_missing: linux-x64")


if __name__ == "__main__":
    unittest.main()
