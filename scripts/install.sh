#!/bin/sh
# Ciao host bootstrap installer.
#
#     curl -fsSL https://ciaooo.app/install.sh | sh
#
# Downloads the latest release archive for this machine from the release
# base, verifies its SHA-256 against the sidecar checksum, and installs the
# `ciao` binary to ~/.local/bin (the same stable path `ciao install` uses).
# Updates after this are handled by the binary itself:
#
#     ciao install --release-base https://ciaooo.app/dist
#
# Site layout expected: /install.sh, /dist/release.json, /dist/ciao-<v>-<t>.tar{,.sha256}
set -eu

BASE="${CIAO_BASE_URL:-https://ciaooo.app/dist}"

# The default is https, but the override is taken verbatim, and over plaintext the checksum is
# worth nothing: the sidecar travels the same interceptable channel as the archive it vouches
# for, so whoever can rewrite one rewrites the other. `ciao install` — the update path in every
# binary already out there — refuses a non-https release base in fetch_release_file(); this keeps
# the bootstrap to the same rule instead of leaving the first install as the weak one.
case "$BASE" in
    https://*) ;;
    *)
        if [ "${CIAO_ALLOW_INSECURE_BASE:-}" = "1" ]; then
            echo "ciao: WARNING: installing over a non-https base ($BASE); nothing is authenticated" >&2
        else
            echo "ciao: refusing a non-https release base: $BASE" >&2
            echo "ciao: the checksum arrives over that same channel, so it proves nothing there." >&2
            echo "ciao: set CIAO_ALLOW_INSECURE_BASE=1 to override for local testing." >&2
            exit 1
        fi
        ;;
esac

case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) target="aarch64-apple-darwin" ;;
    Linux-x86_64) target="x86_64-unknown-linux-gnu" ;;
    # Mirrors install::current_release_target(): refuse rather than guess — and say what
    # would qualify, because an Intel Mac reads a bare refusal as "the install broke".
    *) echo "ciao: no released build for $(uname -s) $(uname -m) — Ciao runs on Apple Silicon Macs and x86_64 Linux" >&2; exit 1 ;;
esac

version="$(curl -fsSL "$BASE/release.json" | sed -n 's/.*"version": *"\([0-9A-Za-z.-]*\)".*/\1/p' | head -n1)"
[ -n "$version" ] || { echo "ciao: could not read version from $BASE/release.json" >&2; exit 1; }

# An existing install is not something to overwrite from here. Dropping a new binary onto a
# machine whose daemon is already running leaves the two at different versions with nothing
# saying so: the CLI is new, the daemon that actually answers is old, and the first thing that
# fails is pairing — which is version-coupled, so the phone shows an error that names nothing
# about versions. Reported 2026-08-01 from a 0.1.7 host.
#
# `ciao install` and `ciao update` already do this correctly: staged swap, refusal while real
# work is live, service restart, and a health check that requires the answering daemon to be the
# version just installed. So hand the upgrade to the binary that is already there rather than
# reimplementing any of it in shell.
installed=""
if [ -x "$HOME/.local/bin/ciao" ]; then
    installed="$("$HOME/.local/bin/ciao" --version 2>/dev/null | awk 'NR==1{print $NF}')"
fi

if [ -n "$installed" ]; then
    if [ "$installed" = "$version" ]; then
        echo "ciao $version is already installed."
        exit 0
    fi
    echo "ciao $installed is installed; $version is available."
    # `curl … | sh` has the script on stdin, so a prompt has to read the terminal directly.
    # Where there is no terminal — CI, a provisioning script — say what to run and change
    # nothing, because an unattended upgrade is exactly the clobber this guard exists to avoid.
    # CIAO_NONINTERACTIVE forces that branch for callers that have a terminal but do not want
    # to be asked.
    if [ -z "${CIAO_NONINTERACTIVE:-}" ] && [ -r /dev/tty ]; then
        printf 'Upgrade now? Running sessions keep running. [y/N] '
        read -r reply < /dev/tty || reply=""
        case "$reply" in
            y|Y|yes|Yes|YES) ;;
            *) echo "Left ciao $installed in place. Upgrade later with: ciao update"; exit 0 ;;
        esac
    else
        echo "ciao: not upgrading without a terminal to ask at." >&2
        echo "ciao: run: ciao update" >&2
        exit 1
    fi
    exec "$HOME/.local/bin/ciao" update --release-base "$BASE"
fi

file="ciao-$version-$target.tar"
tmp="$(mktemp -d)"
stage=""
cleanup() {
    rm -rf "$tmp"
    [ -z "$stage" ] || rm -f "$stage"
}
trap cleanup EXIT

echo "Downloading ciao $version ($target)..."
curl -fsSL -o "$tmp/$file" "$BASE/$file"
curl -fsSL -o "$tmp/$file.sha256" "$BASE/$file.sha256"

if command -v sha256sum >/dev/null 2>&1; then
    (cd "$tmp" && sha256sum -c "$file.sha256" >/dev/null)
else
    (cd "$tmp" && shasum -a 256 -c "$file.sha256" >/dev/null)
fi

tar -xf "$tmp/$file" -C "$tmp" ciao
mkdir -p "$HOME/.local/bin"
# Stage in the destination filesystem so the final replacement is atomic even when
# the system temporary directory lives on another filesystem.
stage="$(mktemp "$HOME/.local/bin/.ciao.install.XXXXXX")"
cp "$tmp/ciao" "$stage"
chmod 755 "$stage"
mv -f "$stage" "$HOME/.local/bin/ciao"
stage=""

echo "Installed ciao $version to ~/.local/bin/ciao"
case ":$PATH:" in
    *:"$HOME/.local/bin":*) ;;
    *)
        # Persist PATH for the next terminal — printing the export line alone left `ciao`
        # command-not-found the next morning. Do it before offering to pair below: an
        # accepted offer execs away and never comes back here.
        case "$(uname -s)-$(basename "${SHELL:-sh}")" in
            *-zsh) rc="$HOME/.zshrc" ;;
            Darwin-bash) rc="$HOME/.bash_profile" ;;
            *-bash) rc="$HOME/.bashrc" ;;
            *) rc="$HOME/.profile" ;;
        esac
        path_line='export PATH="$HOME/.local/bin:$PATH"'
        grep -qsxF "$path_line" "$rc" || printf '\n%s\n' "$path_line" >> "$rc"
        echo "Added ~/.local/bin to PATH in $rc (takes effect in new terminals)."
        ;;
esac

# A fresh install is usually someone the app's Pair screen sent here, phone already in hand,
# so with a terminal to ask at, end at the pairing QR itself instead of naming one more
# command to type. The handover execs `ciao setup --yes` — the spelling every released
# binary understands, and on a host with no paired devices setup already ends at the QR —
# rather than `ciao pair`, which would couple this script's deploy to a host release. The
# same tty checks as the upgrade prompt keep CI and provisioning on the print-only path.
if [ -z "${CIAO_NONINTERACTIVE:-}" ] && [ -r /dev/tty ] && [ -t 1 ]; then
    printf 'Set up this host and show the pairing QR now? [Y/n] '
    read -r reply < /dev/tty || reply=""
    case "$reply" in
        ""|y|Y|yes|Yes|YES) exec "$HOME/.local/bin/ciao" setup --yes ;;
    esac
fi

case ":$PATH:" in
    *:"$HOME/.local/bin":*) echo "Run: ciao pair" ;;
    *) echo 'Run now with: export PATH="$HOME/.local/bin:$PATH" && ciao pair' ;;
esac
