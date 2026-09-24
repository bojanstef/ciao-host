#!/usr/bin/env python3
"""Build one platform's release artifact and native record on a machine that IS that platform.

Runs in `.github/workflows/release.yml` on GitHub-hosted runners (the darwin job on an Apple-silicon
macOS runner, the linux job inside a glibc 2.28 container), one subcommand per artifact:

    python3 scripts/release_build.py native --out dist/native-<platform>.json
    python3 scripts/release_build.py pack --out dist
    python3 scripts/release_build.py manifest --dist dist

`native` runs fmt, clippy and the host suite at HEAD and writes the record only when all three are
green: a file whose presence means "passed" is never written on a red run. `pack` builds
`cargo build --locked --release` for this machine's own target (never a cross build: the runner is
the platform) with the relay token from CIAO_RELAY_TOKEN, and packs exactly the `ciao` binary, the
license and notice files and `install.json` into a deterministic ustar archive plus its sha256
sidecar, byte-identical for equal inputs. `manifest` runs once both platforms have uploaded: it
verifies every file in `dist/`, writes `release.json` (the channel's manifest shape, artifacts only)
and the body of the `release-artifacts` check run that binds every file's digest to this head, so a
consumer can verify what it downloads against what the runners built rather than trust the
artifact store.

The private product repository consumes this file through its pinned `host` submodule: its
`scripts/package_host.py` imports the archive writer and adds `meta.json` and
`provenance-<version>.json`, which name a private revision this repository cannot know.
Publishing is that repository's separately credentialed step; nothing here uploads anywhere.
"""
import argparse
import datetime
import hashlib
import io
import json
import os
import platform
import re
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNNER = "scripts/release_build.py"
CHECK_NAME = "release-artifacts"
TEXT_FILES = ("LICENSE-MIT", "LICENSE-APACHE", "THIRD-PARTY-NOTICES.md")
RELEASE_TARGETS = {"aarch64-apple-darwin", "x86_64-unknown-linux-gnu"}
PLATFORMS = {"aarch64-apple-darwin": "darwin-arm64", "x86_64-unknown-linux-gnu": "linux-x64"}
NATIVE_CHECKS = ("fmt", "clippy", "host_tests")
# The same three checks the private release command ran on the Mac, serial tests because a
# headless runner with no controlling terminal is where a PTY or socket test blocks, and the
# last "test ..." line then names it.
NATIVE_STEPS = (("fmt", ["cargo", "fmt", "--all", "--check"]),
                ("clippy", ["cargo", "clippy", "--locked", "--all-targets", "--", "-D", "warnings"]),
                ("host_tests", ["cargo", "test", "--locked", "-p", "ciao-host", "--", "--test-threads=1"]))
RESULT = re.compile(r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored")
SHA = re.compile(r"[a-f0-9]{40}")
SHA256 = re.compile(r"[a-f0-9]{64}")
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_RECORD = 16 * 1024


class Refused(Exception):
    """One categorical reason, safe for a job log; never a token, a path or raw tool output."""


def run(argv, *, cwd=ROOT, timeout, env=None):
    """The one runner: argv, never a shell; (exit, stdout+stderr). Tests inject their own."""
    try:
        done = subprocess.run(argv, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              stdin=subprocess.DEVNULL, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return 124, b""
    except OSError:
        return 127, b""
    return done.returncode, done.stdout


def utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def detected_host_target():
    """The triple this machine builds natively, or empty if it is not a release build host."""
    machine, system = platform.machine(), platform.system()
    if system == "Darwin" and machine == "arm64":
        return "aarch64-apple-darwin"
    if system == "Linux" and machine == "x86_64":
        return "x86_64-unknown-linux-gnu"
    return ""


def cargo_version(root=ROOT):
    manifest = (Path(root) / "crates/ciao-host/Cargo.toml").read_text()
    for line in manifest.splitlines():
        if line.startswith("version = "):
            value = line.split('"')[1] if line.count('"') >= 2 else ""
            if VERSION.fullmatch(value):
                return value
            break
    raise Refused("package_version_unreadable")


def deterministic_tar(members):
    """Plain ustar, fixed order, zeroed metadata: byte-identical for equal inputs."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, data, mode in members:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = mode
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def archive_members(binary, version, target, root=ROOT):
    install = json.dumps({"v": 1, "version": version, "target": target}) + "\n"
    members = [("ciao", binary, 0o755)]
    for text in TEXT_FILES:
        members.append((text, (Path(root) / text).read_bytes(), 0o644))
    members.append(("install.json", install.encode(), 0o644))
    return members


def head_and_clean(runner, root):
    code, out = runner(["git", "-C", str(root), "rev-parse", "HEAD"], timeout=60)
    head = out.decode("utf-8", "replace").strip()
    if code or not SHA.fullmatch(head):
        raise Refused("head_unreadable")
    code, out = runner(["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"], timeout=60)
    if code or out.strip():
        raise Refused("source_not_clean")
    return head


def toolchain(runner, root):
    code, out = runner(["cargo", "--version"], cwd=root, timeout=120)
    words = out.decode("utf-8", "replace").split()
    if code or len(words) < 2 or not re.fullmatch(r"[A-Za-z0-9_.+-]{1,64}", words[1]):
        raise Refused("toolchain_unreadable")
    return words[1]


def native_record(runner, root, out, *, platform_name=None, emit=print):
    """fmt, clippy and the host suite at the clean HEAD; the record only on green."""
    root = Path(root)
    target = detected_host_target()
    if not target:
        raise Refused("unsupported_build_host")
    head = head_and_clean(runner, root)
    version = toolchain(runner, root)
    checks = {}
    for name, argv in NATIVE_STEPS:
        emit(f"::group::{name}")
        code, output = runner(argv, cwd=root, timeout=3600)
        text = output.decode("utf-8", "replace")
        emit(text[-65536:])
        emit("::endgroup::")
        if name == "host_tests":
            results = RESULT.findall(text)
            passed = sum(int(p) for _, p, _, _ in results)
            failed = sum(int(f) for _, _, f, _ in results)
            if code or not results or failed or passed < 1 or any(status != "ok" for status, *_ in results):
                raise Refused("host_tests_failed")
            checks[name] = passed
        else:
            if code:
                raise Refused(f"{name}_failed")
            checks[name] = 0
    record = {"v": 1, "runner": RUNNER, "runner_sha256": sha256(Path(__file__).resolve().read_bytes()),
              "head": head, "platform": platform_name or PLATFORMS[target], "toolchain": version, "checks": checks,
              "observed_utc": utc()}
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(canonical(record) + "\n")
    return record


def relay_token(environ=os.environ):
    """The relay admission token, from the environment only: on a runner it is the repository
    secret CIAO_RELAY_TOKEN. A release host refuses to compile without it, deliberately, so a
    shipped daemon can never fall back to Number 0's relays; refusing here names the reason
    instead of failing deep in the build."""
    value = environ.get("CIAO_RELAY_TOKEN", "")
    if not value.strip():
        raise Refused("relay_token_required")
    return value


def build_binary(runner, root, target, environ=os.environ):
    """`cargo build --locked --release` for this machine's own target. Only this target's output
    is removed first, so a failed or no-op build cannot ship the previous run's binary."""
    root = Path(root)
    if target != detected_host_target():
        raise Refused("cross_build_refused")
    environment = dict(environ)
    environment["CIAO_RELAY_TOKEN"] = relay_token(environ)
    binary = root / "target" / target / "release" / "ciao"
    binary.unlink(missing_ok=True)
    code, _ = runner(["cargo", "build", "--locked", "--release", "--target", target], cwd=root, timeout=3600, env=environment)
    if code or not binary.is_file() or binary.is_symlink() or binary.stat().st_size == 0:
        raise Refused("release_build_failed")
    return binary


NOTARY_KEYS = ("CIAO_NOTARY_KEY_PATH", "CIAO_NOTARY_KEY_ID", "CIAO_NOTARY_ISSUER")
NOTARY_STATUS = re.compile(rb'"status"\s*:\s*"([A-Za-z ]+)"')
NOTARY_ID = re.compile(rb'"id"\s*:\s*"([0-9a-fA-F-]{36})"')


def notarize(runner, binary, target, environ=os.environ, emit=print):
    """Developer ID signature with the hardened runtime, then Apple's notary service, for the macOS
    binary only. Without CIAO_DEVELOPER_ID the binary keeps the linker's ad-hoc signature and the job
    log says so; with it, every later step is required. No ticket is stapled: a bare Mach-O cannot
    carry one, so Gatekeeper looks it up online. Returns whether the binary was notarized."""
    if not target.endswith("-apple-darwin"):
        return False
    identity = environ.get("CIAO_DEVELOPER_ID", "").strip()
    if not identity:
        emit("Not notarized: CIAO_DEVELOPER_ID is unset, so the binary keeps its ad-hoc signature")
        return False
    key = {name: environ.get(name, "").strip() for name in NOTARY_KEYS}
    if not all(key.values()):
        raise Refused("notary_credentials_required")
    code, _ = runner(["codesign", "--force", "--options", "runtime", "--timestamp", "--sign", identity, str(binary)],
                     timeout=300)
    if code:
        raise Refused("codesign_failed")
    upload = binary.parent / "ciao-notary.zip"
    upload.unlink(missing_ok=True)
    code, _ = runner(["ditto", "-c", "-k", "--keepParent", str(binary), str(upload)], timeout=300)
    if code:
        raise Refused("notary_upload_unpackable")
    code, out = runner(["xcrun", "notarytool", "submit", str(upload), "--key", key["CIAO_NOTARY_KEY_PATH"],
                        "--key-id", key["CIAO_NOTARY_KEY_ID"], "--issuer", key["CIAO_NOTARY_ISSUER"],
                        "--wait", "--timeout", "30m", "--output-format", "json"], timeout=2400)
    status = NOTARY_STATUS.findall(out or b"")
    if code or status[-1:] != [b"Accepted"]:
        # The submission id is safe to log, and `xcrun notarytool log <id>` says what Apple refused.
        submission = NOTARY_ID.findall(out or b"")
        raise Refused("notarization_not_accepted" + (f": {submission[-1].decode()}" if submission else ""))
    emit("Signed with Developer ID (hardened runtime) and notarized")
    return True


def pack(runner, root, out, environ=os.environ, emit=print):
    root, out = Path(root), Path(out)
    target = detected_host_target()
    if not target:
        raise Refused("unsupported_build_host")
    head_and_clean(runner, root)
    version = cargo_version(root)
    binary = build_binary(runner, root, target, environ)
    notarize(runner, binary, target, environ, emit)
    archive = deterministic_tar(archive_members(binary.read_bytes(), version, target, root))
    name = f"ciao-{version}-{target}.tar"
    out.mkdir(parents=True, exist_ok=True)
    (out / name).write_bytes(archive)
    digest = sha256(archive)
    (out / f"{name}.sha256").write_text(f"{digest}  {name}\n")
    emit(f"Packed {name} ({len(archive)} bytes, sha256 {digest})")
    return {"file": name, "target": target, "version": version, "sha256": digest, "bytes": len(archive)}


def read_record(path, head):
    """A native record this script wrote, at this head; the same shape the private reader accepts."""
    try:
        value = json.loads(path.read_text())
        checks = value["checks"]
        if (set(value) != {"v", "runner", "runner_sha256", "head", "platform", "toolchain", "checks", "observed_utc"}
                or value["v"] != 1 or value["runner"] != RUNNER or value["head"] != head
                or value["platform"] not in PLATFORMS.values() or not SHA256.fullmatch(value["runner_sha256"])
                or set(checks) != set(NATIVE_CHECKS) or any(type(v) is not int or v < 0 for v in checks.values())
                or checks["fmt"] != 0 or checks["clippy"] != 0 or checks["host_tests"] < 1):
            raise ValueError()
    except (OSError, ValueError, KeyError, TypeError):
        raise Refused("native_record_invalid") from None
    return value


def manifest(runner, root, dist, *, run_url=None, run_id=None, emit=print):
    """Both platforms' archives, sidecars and records in `dist/`, verified, then `release.json` and
    the check-run body. Anything missing, extra or disagreeing is a refusal by name. `run_id` is this
    workflow run's, carried on the check run as `external_id`: GitHub files a check run created with
    the workflow token under whichever Actions suite it likes and rewrites `details_url` to the check
    run's own page (observed on the first main run, 2026-09-19), so `external_id` is the one field
    that binds the check run to the run whose artifacts it describes."""
    root, dist = Path(root), Path(dist)
    if run_id is not None and not re.fullmatch(r"[1-9][0-9]{0,15}", str(run_id)):
        raise Refused("run_id_invalid")
    head = head_and_clean(runner, root)
    version = cargo_version(root)
    artifacts, records, files = [], {}, {}
    for target in sorted(RELEASE_TARGETS):
        name = f"ciao-{version}-{target}.tar"
        archive_path, sidecar_path = dist / name, dist / f"{name}.sha256"
        if not archive_path.is_file() or not sidecar_path.is_file():
            raise Refused(f"artifact_missing: {PLATFORMS[target]}")
        raw = archive_path.read_bytes()
        if not 0 < len(raw) <= MAX_ARCHIVE:
            raise Refused("archive_size_out_of_bounds")
        digest = sha256(raw)
        if sidecar_path.read_text() != f"{digest}  {name}\n":
            raise Refused("archive_sidecar_mismatch")
        check_archive(raw, version, target, root)
        artifacts.append({"version": version, "target": target, "file": name, "sha256": digest, "bytes": len(raw)})
        files[name], files[f"{name}.sha256"] = digest, sha256(sidecar_path.read_bytes())
        record_path = dist / f"native-{PLATFORMS[target]}.json"
        if not record_path.is_file() or record_path.stat().st_size > MAX_RECORD:
            raise Refused(f"native_record_missing: {PLATFORMS[target]}")
        record = read_record(record_path, head)
        if record["platform"] != PLATFORMS[target]:
            raise Refused("native_record_platform_mismatch")
        records[record["platform"]] = {"toolchain": record["toolchain"], "checks": record["checks"]}
        files[record_path.name] = sha256(record_path.read_bytes())
    extra = sorted(p.name for p in dist.iterdir() if p.name not in files and p.name != "release.json")
    if extra:
        raise Refused("unexpected_files_in_dist")
    release = json.dumps({"v": 1, "artifacts": artifacts}, indent=2) + "\n"
    (dist / "release.json").write_text(release)
    files["release.json"] = sha256(release.encode())
    record = {"v": 1, "head": head, "version": version, "runner": RUNNER,
              "runner_sha256": sha256(Path(__file__).resolve().read_bytes()),
              "artifacts": artifacts, "platforms": records, "files": files}
    body = {"name": CHECK_NAME, "head_sha": head, "status": "completed", "conclusion": "success",
            "output": {"title": f"Release artifacts {version} at {head[:12]}", "summary": canonical(record)}}
    if run_url:
        body["details_url"] = run_url
    if run_id is not None:
        body["external_id"] = str(run_id)
    (dist / "check-run.json").write_text(canonical(body) + "\n")
    emit(f"release.json for {version} at {head[:12]}: {len(files)} files bound to the {CHECK_NAME} check")
    return record


def check_archive(raw, version, target, root):
    """Structural integrity of one archive against this checkout's own text files."""
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
            members = tar.getmembers()
            names = [m.name for m in members]
            if names != ["ciao", *TEXT_FILES, "install.json"] or any(not m.isfile() for m in members):
                raise ValueError()
            if tar.getmember("ciao").mode != 0o755 or tar.getmember("ciao").size == 0:
                raise ValueError()
            for text in TEXT_FILES:
                if tar.extractfile(text).read() != (Path(root) / text).read_bytes():
                    raise ValueError()
            if json.loads(tar.extractfile("install.json").read()) != {"v": 1, "version": version, "target": target}:
                raise ValueError()
    except (tarfile.TarError, KeyError, ValueError, OSError):
        raise Refused("invalid_release_archive") from None


def main(argv=None, *, runner=run, environ=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT)
    commands = parser.add_subparsers(dest="command", required=True)
    native = commands.add_parser("native", help="fmt, clippy and the host suite; the record only on green")
    native.add_argument("--out", type=Path, required=True)
    packer = commands.add_parser("pack", help="release build and deterministic archive for this machine's target")
    packer.add_argument("--out", type=Path, default=ROOT / "dist")
    assembler = commands.add_parser("manifest", help="verify both platforms' files, write release.json and the check-run body")
    assembler.add_argument("--dist", type=Path, default=ROOT / "dist")
    assembler.add_argument("--run-url", help="this workflow run's page, carried on the check run")
    assembler.add_argument("--run-id", help="this workflow run's id, carried on the check run as external_id")
    args = parser.parse_args(argv)
    environ = os.environ if environ is None else environ
    try:
        if args.command == "native":
            print(canonical(native_record(runner, args.root, args.out)))
        elif args.command == "pack":
            print(canonical(pack(runner, args.root, args.out, environ)))
        else:
            print(canonical(manifest(runner, args.root, args.dist, run_url=args.run_url, run_id=args.run_id)))
        return 0
    except Refused as error:
        print(f"::error::release_build: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
