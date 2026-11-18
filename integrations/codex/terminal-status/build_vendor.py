#!/usr/bin/env python3
"""Build a local Codex terminal-status candidate; never install or publish it.

The checkout must be clean at the exact public upstream revision. The patch preserves all
third-party dependency pins and the upstream version; artifact provenance distinguishes it.
Use a new private Cargo home; reused dependency sources are not provenance-bound inputs.
The candidate retains the upstream LICENSE and NOTICE alongside its provenance.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import shutil
import stat
import subprocess
import sys
import tempfile

BASE_COMMIT = "d32063f96c2dff1dc96af839b3952abb6acfeda4"
BASE_VERSION = "0.169.0"
FEATURE_VERSION = 1
CARGO_HOME_POLICY = "new-private-home-no-reused-dependency-sources"
PATCH = Path(__file__).with_name("codex-0.169.0.patch")


class Refused(Exception):
    pass


def checked(argv, *, cwd, env=None, timeout=60, capture=True):
    clean_env = dict(os.environ if env is None else env)
    for name in list(clean_env):
        if name.startswith("GIT_"):
            del clean_env[name]
    clean_env.update({
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
    })
    if Path(argv[0]).name == "git":
        # Repository-local fsmonitor hooks are not grounded compiler inputs and can execute
        # arbitrary local commands even for status. Disable them without editing Git settings.
        argv = [argv[0], "-c", "core.fsmonitor=false", "-c", f"core.hooksPath={os.devnull}", *argv[1:]]
    try:
        process = subprocess.Popen(
            argv, cwd=cwd, env=clean_env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            start_new_session=True,
        )
        try:
            stdout, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            # Cargo owns a tree of compilers and build scripts. Its timeout must stop that
            # private process group, rather than leave orphaned native builds behind.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()
            raise Refused("candidate build operation timed out") from error
    except OSError as error:
        raise Refused("candidate build operation failed") from error
    if process.returncode:
        raise Refused("candidate build operation failed")
    return stdout.decode("utf-8", errors="strict").rstrip("\r\n") if capture else ""


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def exclusive_copy(source, destination):
    if source.is_symlink() or not source.is_file():
        raise Refused("candidate input is not a regular file")
    with source.open("rb") as original, destination.open("xb") as copied:
        shutil.copyfileobj(original, copied, length=1024 * 1024)


def relative_source_path(path):
    relative = Path(path)
    if (not path or relative.is_absolute() or ".." in relative.parts
            or ".git" in relative.parts or relative.as_posix() != path):
        raise Refused("vendor source path is invalid")
    return relative


def base_tree(checkout):
    if checked(["git", "for-each-ref", "--format=%(refname)", "refs/replace"], cwd=checkout):
        raise Refused("vendor checkout contains replacement objects")
    records = {}
    listing = checked(["git", "ls-tree", "-r", "-z", "--full-tree", BASE_COMMIT], cwd=checkout)
    for entry in listing.split("\0"):
        if not entry:
            continue
        metadata, path = entry.split("\t", 1)
        mode, kind, object_id = metadata.split(" ")
        relative_source_path(path)
        if kind != "blob" or mode not in ("100644", "100755", "120000"):
            raise Refused("vendor source contains an unsupported tracked object")
        records[path] = (mode, object_id)
    if not records:
        raise Refused("vendor source tree is empty")
    return records


def file_record(checkout, path):
    relative = relative_source_path(path)
    parent = checkout
    for component in relative.parts[:-1]:
        parent /= component
        if not stat.S_ISDIR(parent.lstat().st_mode):
            raise Refused("vendor source parent is not a directory")
    file = checkout / relative
    before = file.lstat()
    if stat.S_ISLNK(before.st_mode):
        content = os.fsencode(os.readlink(file))
        blob = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
        sha256 = hashlib.sha256(content).hexdigest()
        mode = "120000"
    elif stat.S_ISREG(before.st_mode):
        blob_hash = hashlib.sha1(b"blob " + str(before.st_size).encode() + b"\0")
        content_hash = hashlib.sha256()
        count = 0
        with file.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                count += len(chunk)
                blob_hash.update(chunk)
                content_hash.update(chunk)
        if count != before.st_size:
            raise Refused("vendor source changed while being read")
        blob, sha256 = blob_hash.hexdigest(), content_hash.hexdigest()
        mode = "100755" if before.st_mode & stat.S_IXUSR else "100644"
    else:
        raise Refused("vendor source file is invalid")
    after = file.lstat()
    if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_mode)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_mode)):
        raise Refused("vendor source changed while being read")
    return {"mode": mode, "git_blob": blob, "sha256": sha256}


def patch_paths(checkout):
    paths = set()
    listing = checked(["git", "apply", "--numstat", "-z", str(PATCH)], cwd=checkout)
    for entry in listing.split("\0"):
        if entry:
            path = entry.split("\t", 2)[-1]
            relative_source_path(path)
            paths.add(path)
    if not paths:
        raise Refused("vendor patch is empty")
    return paths


def validate_build_inputs(checkout, allowed, cargo_home=None):
    # Porcelain deliberately omits ignored files. Cargo does not: a legacy config can
    # override config.toml, and build scripts can read arbitrary ignored source inputs.
    for flags in (("--exclude-standard",), ("--ignored", "--exclude-standard")):
        extras = checked(["git", "ls-files", "--others", "-z", *flags], cwd=checkout)
        if any(path not in allowed for path in extras.split("\0") if path):
            raise Refused("vendor source contains unbound untracked or ignored inputs")
    for path in allowed:
        file = checkout / path
        if file.is_symlink():
            try:
                target = file.resolve(strict=True).relative_to(checkout).as_posix()
            except (ValueError, OSError, RuntimeError) as error:
                raise Refused("vendor source contains an external symlink input") from error
            if target not in allowed or not (checkout / target).is_file():
                raise Refused("vendor symlink target is not a bound source file")
    # Cargo walks from cwd to the filesystem root, regardless of the Git boundary.
    for ancestor in checkout.parents:
        for name in ("config", "config.toml"):
            config = ancestor / ".cargo" / name
            if config.exists() or config.is_symlink():
                raise Refused("unbound ancestor Cargo configuration")
    if cargo_home is not None:
        for name in ("config", "config.toml", "credentials", "credentials.toml"):
            config = cargo_home / name
            if config.exists() or config.is_symlink():
                raise Refused("vendor Cargo home must not contain configuration or credentials")


def compiler_binding(checkout, cargo_home, sources, env):
    validate_build_inputs(checkout, sources, cargo_home)
    return {
        "rustc": checked(["rustc", "--version", "--verbose"], cwd=checkout / "codex-rs", env=env),
        "cargo": checked(["cargo", "--version", "--verbose"], cwd=checkout / "codex-rs", env=env),
        "cargo_configs": {path: record for path, record in sources.items()
                          if path in (".cargo/config", ".cargo/config.toml",
                                      "codex-rs/.cargo/config", "codex-rs/.cargo/config.toml")},
        "environment": env,
        "cargo_home_policy": CARGO_HOME_POLICY,
    }


def validate_source(checkout):
    if Path(checked(["git", "rev-parse", "--show-toplevel"], cwd=checkout)).resolve() != checkout:
        raise Refused("checkout must name the public repository root")
    if checked(["git", "rev-parse", "HEAD"], cwd=checkout) != BASE_COMMIT:
        raise Refused("checkout is not the grounded public Codex revision")
    for path, expected in base_tree(checkout).items():
        actual = file_record(checkout, path)
        if (actual["mode"], actual["git_blob"]) != expected:
            raise Refused("vendor source differs from the grounded public tree")
    if checked(["git", "status", "--porcelain", "--untracked-files=all"], cwd=checkout):
        raise Refused("checkout must be clean before applying the vendor patch")
    validate_build_inputs(checkout, base_tree(checkout))
    if not PATCH.is_file():
        raise Refused("the reviewed vendor patch is missing")
    checked(["git", "apply", "--check", str(PATCH)], cwd=checkout)


def source_binding(checkout):
    base = base_tree(checkout)
    paths = patch_paths(checkout)
    changed = checked(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"], cwd=checkout
    )
    if any(entry[3:] not in paths for entry in changed.split("\0") if entry):
        raise Refused("vendor source contains changes outside the reviewed patch")
    validate_build_inputs(checkout, set(base) | paths)
    records = {}
    for path in sorted(set(base) | paths):
        actual = file_record(checkout, path)
        if path not in paths and (actual["mode"], actual["git_blob"]) != base[path]:
            raise Refused("vendor source contains changes outside the reviewed patch")
        if path in paths and actual["mode"] == "120000":
            raise Refused("vendor patch source file is invalid")
        records[path] = actual
    return records


def build(args):
    checkout = args.checkout.resolve(strict=True)
    output = args.out.resolve()
    cargo_home = args.cargo_home.resolve()
    if (not checkout.is_dir() or checkout == output or checkout in output.parents
            or output in checkout.parents):
        raise Refused("artifact output must be separate from the public source checkout")
    global_cargo_homes = {Path.home().joinpath(".cargo").resolve()}
    if os.environ.get("CARGO_HOME"):
        global_cargo_homes.add(Path(os.environ["CARGO_HOME"]).expanduser().resolve())
    uses_global_cache = any(
        cargo_home == global_home
        or (cargo_home.exists() and global_home.exists() and cargo_home.samefile(global_home))
        for global_home in global_cargo_homes
    )
    if (uses_global_cache or cargo_home == checkout
            or checkout in cargo_home.parents or cargo_home in checkout.parents
            or cargo_home == output or output in cargo_home.parents or cargo_home in output.parents):
        raise Refused("vendor Cargo home must be a separate dedicated cache")
    if any((cargo_home / name).exists() or (cargo_home / name).is_symlink()
           for name in ("config", "config.toml", "credentials", "credentials.toml")):
        raise Refused("vendor Cargo home must not contain configuration or credentials")
    # --locked pins resolution, not mutable extracted Git/registry cache bytes. Even an
    # empty existing directory is not ours to trust. Check the original path as well so
    # resolve() cannot hide a dangling home symlink. --check never reserves this path.
    if args.cargo_home.exists() or args.cargo_home.is_symlink() or cargo_home.exists():
        raise Refused("vendor Cargo home already exists; choose a new private Cargo home")
    if args.jobs < 1 or args.jobs > 4:
        raise Refused("candidate builds require between one and four jobs")
    validate_source(checkout)
    patch_digest = digest(PATCH)
    if args.check:
        return {"v": 1, "source_commit": BASE_COMMIT, "patch_sha256": patch_digest, "applicable": True}
    artifact = output / "codex"
    manifest_path = output / "provenance.json"
    if args.out.exists() or args.out.is_symlink():
        raise Refused("candidate output already exists; choose a new output directory")
    # Reserve a new private directory before source mutation. Existing bin directories and
    # dangling output symlinks cannot turn this artifact build into an installation.
    # Exclusive reservation also refuses a home created after the preflight check.
    # Failed builds consume this path too: retries must fetch into another new home.
    cargo_home.mkdir(mode=0o700, parents=True, exist_ok=False)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    checked(["git", "apply", str(PATCH)], cwd=checkout)
    sources = source_binding(checkout)
    rust = checkout / "codex-rs"
    build_env = {name: os.environ[name] for name in (
        "PATH", "HOME", "RUSTUP_HOME", "TMPDIR", "LANG", "LC_ALL", "SSL_CERT_FILE",
        "SSL_CERT_DIR", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY",
    ) if name in os.environ}
    build_env.update({
        "CARGO_HOME": str(cargo_home),
        "CARGO_NET_GIT_FETCH_WITH_CLI": "true",
        "CARGO_BUILD_JOBS": str(args.jobs),
    })
    # A clean source tree does not attest ignored Cargo outputs. Build into a fresh private
    # target directory, never the checkout's pre-existing target/cache contents.
    with tempfile.TemporaryDirectory(prefix=".build-", dir=output) as target:
        build_env["CARGO_TARGET_DIR"] = target
        compiler = compiler_binding(checkout, cargo_home, sources, build_env)
        toolchain = compiler["rustc"]
        checked(
            ["cargo", "build", "--locked", "--profile", args.profile,
             "-p", "codex-cli", "--bin", "codex", "-j", str(args.jobs)],
            cwd=rust, env=build_env, timeout=7200, capture=False,
        )
        if (checked(["git", "rev-parse", "HEAD"], cwd=checkout) != BASE_COMMIT
                or digest(PATCH) != patch_digest or source_binding(checkout) != sources
                or compiler_binding(checkout, cargo_home, sources, build_env) != compiler):
            raise Refused("candidate source binding changed during the build")
        # Original CLI version stays numeric so existing vendor admission remains unchanged.
        source = Path(target) / args.profile / "codex"
        if source.is_symlink() or not source.is_file():
            raise Refused("candidate executable is not a regular build artifact")
        if checked([str(source), "--version"], cwd=rust, env=build_env) != f"codex-cli {BASE_VERSION}":
            raise Refused("candidate did not report the grounded base version")
        # Exclusive creation refuses existing files and symlinks, including dangling ones.
        exclusive_copy(source, artifact)
        artifact.chmod(0o755)
    attribution_digests = {}
    for name in ("LICENSE", "NOTICE"):
        if name not in sources:
            raise Refused("candidate upstream attributions are missing")
        destination = output / name
        exclusive_copy(checkout / name, destination)
        checksum = digest(destination)
        if checksum != sources[name]["sha256"]:
            raise Refused("candidate attribution binding changed")
        attribution_digests[f"{name.lower()}_sha256"] = checksum
    manifest = {
        "v": 1,
        "vendor": "codex",
        "base_version": BASE_VERSION,
        "source_commit": BASE_COMMIT,
        "terminal_status_version": FEATURE_VERSION,
        "patch_sha256": patch_digest,
        "source_files_sha256": hashlib.sha256(json.dumps(sources, sort_keys=True).encode()).hexdigest(),
        "binary_sha256": digest(artifact),
        "platform": platform.system().lower(),
        "architecture": platform.machine(),
        "toolchain": toolchain,
        "compiler_inputs_sha256": hashlib.sha256(json.dumps(compiler, sort_keys=True).encode()).hexdigest(),
        "cargo_version": compiler["cargo"],
        "cargo_config_sha256": {path: record["sha256"] for path, record in compiler["cargo_configs"].items()},
        "ancestor_and_cargo_home_config": "absent-checked-before-and-after",
        "cargo_home_policy": compiler["cargo_home_policy"],
        "profile": args.profile,
        "official_binary": False,
        "installed": False,
        **attribution_digests,
    }
    with manifest_path.open("x", encoding="utf-8") as manifest_file:
        manifest_file.write(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True, help="clean public rust-v0.169.0 checkout")
    parser.add_argument("--out", type=Path, required=True, help="new candidate artifact directory")
    parser.add_argument("--cargo-home", type=Path, required=True, help="new private vendor Cargo home (must not exist, even empty)")
    parser.add_argument("--profile", choices=("dev-small", "release"), default="dev-small")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--check", action="store_true", help="verify revision and patch applicability only")
    try:
        print(json.dumps(build(parser.parse_args()), indent=2))
    except (Refused, OSError, UnicodeError) as error:
        # Operation labels, never captured vendor output or local credentials.
        print(f"refused: {error if isinstance(error, Refused) else 'candidate filesystem operation failed'}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
