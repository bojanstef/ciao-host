# Local Codex terminal identity, version 1

Codex's standalone TUI can authenticate its hooks through process ancestry. A shared
app-server cannot identify a terminal that way: several TUIs share one backend, and a
thread subscription can outlive the conversation displayed by its TUI. Attached observation
therefore needs an independent, kernel-authenticated terminal identity.

This interface requires the accompanying Codex TUI patch; stock Codex 0.169.0 does not
implement it. It does not change the public Ciao protocol or authorize vendor commands.

## Transport and ownership

The native TUI serves `$CODEX_HOME/tui-status/<pid>.sock` (default home `~/.codex`). The
directory is private to its user (0700), the socket is 0600, and neither is a symlink.
The service accepts only same-user Unix peers. A client authenticates the server's actual
PID through Unix peer credentials and checks its process incarnation before and after
the query. The filename and any JSON PID are never authentication.

One connection accepts one newline-terminated request, bounded to 256 bytes and 500 ms:

```json
{"v":1,"type":"status"}
```

It returns one newline-terminated JSON snapshot, bounded to 16384 bytes, then closes.
There are at most four concurrent queries. This service has no command, prompt, file,
configuration, shell, or transcript operation. Errors do not echo input or raw paths.

## Snapshot

See `examples.json`. Fields are:

- `v`: the integer 1.
- `generation`: a positive, monotonically increasing connection/selection revision.
- `connection.kind`: `embedded`, `local_daemon`, or `remote`.
- `connection.state`: `connected` or `disconnected`.
- `connection.server`: null except for a connected local daemon, where it contains `pid`
  and `identity`. The TUI captures both from its actual Unix backend connection, never
  from a request, inherited environment, workspace, terminal title or PID file.
- `displayed_thread_id`: the vendor UUID currently displayed, or null. A history/replay
  view may have a displayed thread without a live attachment.
- `attached_thread_ids`: at most 64 distinct UUIDs representing actual live attachments.
  Subscriber membership alone is not proof of a foreground conversation.

A backend identity is `linux:<boot-uuid>:<start-ticks>` or
`macos:<boot-uuid>:<kernel-process-unique-id>`. Its numeric component is canonical unsigned
decimal. The consumer independently reads and compares that kernel process incarnation.

The TUI owns the snapshot. It invalidates connection claims before disconnect/reconnect,
clears foreground selection before switching, and publishes a new selection only after
successful attachment. Socket cleanup and process exit invalidate the endpoint; no timestamp,
mtime, lease or cached verdict establishes liveness. Remote backends confer no local route.

## Ciao acceptance

Standalone hooks retain the existing same-user, process-descent and interactive-TUI checks.
Shared hooks first prove descent from the claimed local Codex app-server. Ciao then requires
exactly one supported interactive TUI whose authenticated snapshot:

1. Is connected to that exact backend PID and kernel incarnation.
2. Displays the hook's exact thread and has it in the live attachment set.
3. Still names the same TUI incarnation and generation when a route is used.

Missing, oversized, malformed, stale, remote, disconnected or ambiguous evidence is refused.
Unrecognized vocabulary is tallied without recording values or content. Neither cwd, argv
resume arguments, titles, timestamps, a shared socket nor a rollout holder alone establishes
this association. Shared-backend hooks remain read-only observations and expose no takeover.
A fresh read-only hook association may use a newly authenticated selection generation for the
same producer, thread and TUI incarnations. This is not continuity: replacing any binding
revokes its old opaque route, including an ABA back to the same UUID. Route records bind the
exact terminal proof and are checked again across asynchronous resolution/use. A pending hook
cannot borrow another registration's internal correlation token; history reconstruction may
refresh only its same-connection receipt, not stale phone commands or cursors.

The backend is never a terminal exit target. Foreign rollout ownership continues to refuse adoption, even after
a TUI exits, until the vendor actually releases it.

Validation must cover standalone and shared mode, two TUIs, same-thread ambiguity, thread
switches and history, idle resume before hooks, PID reuse, backend and Ciao restarts,
disconnects, foreign writers, and refusal to target the shared backend during takeover.

## Building a candidate

`codex-0.169.0.patch` applies to the exact public upstream commit
`d32063f96c2dff1dc96af839b3952abb6acfeda4` (`rust-v0.169.0`, annotated tag object
`a41fe5b443652cbdbee57717fbb9fd78d8d8b32a`). This supersedes only the earlier patch's
0.166.0 base, not the ownership or authentication contract. It adds this read-only endpoint,
the remote client's acknowledged-attachment/liveness tracking, and native backend identity.
It changes neither model behavior nor Ciao's app-server method vocabulary. The lockfile part
normalizes the tag's workspace package versions from `0.0.0` to the manifest's `0.169.0` and
adds two local dependency edges; third-party dependency versions and checksums are unchanged.
The upstream Apache-2.0 license and notice are included as `UPSTREAM-LICENSE` and
`UPSTREAM-NOTICE`.

Use a clean checkout of that exact public commit and a **new, nonexistent** Cargo home
(do not pre-create it, even as an empty directory):

```sh
python3 integrations/codex/terminal-status/build_vendor.py \
  --checkout /tmp/codex-terminal-source \
  --cargo-home /tmp/codex-terminal-cargo \
  --out /tmp/codex-terminal-candidate --check
```

`--check` verifies the inputs without creating a Cargo home, target or artifact directory.
Run again without `--check` to apply the patch and build, using at most four jobs. The default
`dev-small` profile is for validation; `--profile release` selects an optimized candidate.
The script verifies the complete public source tree, binds source files before/after building,
and rejects all unbound untracked/ignored files (including old checkout targets and legacy
`.cargo/config` overrides), external/unbound symlink targets, and ancestor Cargo configurations.
The builder exclusively reserves the Cargo home as a new private (0700) directory before
patching or compiling. Every pre-existing home is refused, including empty directories and
symlinks: `--locked` and a fresh target do not authenticate mutable, previously extracted Git
or registry dependency sources. No dependency cache, configuration or credentials are copied;
normal public dependency downloads populate the new home. Config and credential absence is
also checked before and after the compiler runs; no private global config is imported.
Provenance explicitly records `cargo_home_policy: new-private-home-no-reused-dependency-sources`
and binds it with the sanitized compiler environment, verbose Rust/Cargo versions and
checked-in effective Cargo config bytes. This costs additional network traffic, disk space
and build time on every candidate. After a failed build, keep its evidence and retry with
another clean checkout and new Cargo-home/output paths, never the consumed cache or target.
Use a clean disposable checkout, not one containing ignored build products. The builder
uses a fresh target directory, and writes a new `codex` binary plus `provenance.json` outside
the source checkout. It never installs, replaces a running process, uploads or publishes.

The candidate keeps the numeric `codex-cli 0.169.0` base version so existing admission rules
remain unchanged. It is **not the official Codex binary**: provenance binds its upstream
commit, feature version, patch, source inputs and resulting binary digest. Stock standalone
Codex remains supported; stock shared mode cannot provide this new identity proof. A later
official update without the endpoint confers no shared terminal association.

### Persisted workspace side chats

The displayed identity follows the actual focused conversation, not the primary thread,
parked companion, saved-tab list or background subscriptions. Saved-chat preparation is
provisional: neither an incoming channel nor a transport response alone grants foreground
ownership. A live channel and an acknowledged attachment must agree, and queued transcript
Park/Reset/Finish events must settle. Chooser focus publishes no displayed conversation.
Channels belonging to another backend are excluded, and request-only session views cannot
attest a connection. Closed/history-only restores remain replay-only. Focus changes invalidate
the published generation before asynchronous selection work; socket queries independently
recheck transport liveness even while the UI awaits a backend response. Sidebar presentation
mutations share one synchronous invalidation owner, including mouse selection of a saved row
from a main-focused chooser and keyboard refocus. Transport attachment membership and its
monotonic revision share one lock: withdraw/re-ack of the same UUID cannot reuse a status
generation, even with no intervening query or UI event drain. Unchanged membership/snapshots
do not advance revisions. Request-only handles and queued close/archive/delete notifications
update the same transport revision.

Focused vendor unit coverage lives in the generated patch: `terminal_status` (including the
multiple persisted side-chat restart/focus journey with local mock responses),
`tui_status::tests`, `closed_saved_chat_keeps_its_live_read_receipt_during_install`,
`saved_chat_replays_approval_after_a_stale_runtime_close`, app-server-client `terminal_`,
daemon `terminal_process_identity`, and UDS `peer_credentials`. The held-store-lock mouse test
queries the actual Unix socket while the real UI dispatcher is pending, then checks keyboard
refocus; the attachment tests cover unsampled ABA and request-only/queued lifecycle paths.
Saved-chat fixtures use a bounded 16-MiB test thread stack and a 120-second deadline (the
native debug future overflows libtest's default stack). These tests require no
subscription/model calls. In the patched disposable source, with a dedicated Cargo home/target:

```sh
cargo test --locked --profile dev-small -j 4 --lib \
  -p codex-tui -p codex-app-server-client -p codex-app-server-daemon -p codex-uds -- \
  terminal_status terminal_attachment remote_terminal_binding terminal_process_identity \
  tui_status::tests peer_credentials \
  closed_saved_chat_keeps_its_live_read_receipt_during_install \
  saved_chat_replays_approval_after_a_stale_runtime_close \
  fork_releases_a_provisional_saved_chat_on_its_original_connection --test-threads=1
```

Keep these explicit filters: a broad `terminal_` across all four packages also selects
unrelated upstream UI tests, some of which overflow libtest's default debug stack.

A local native test pass is not Linux, device or runtime acceptance.

Run builder regressions with:

```sh
python3 -B -m unittest discover -s integrations/codex/terminal-status -p test_build_vendor.py
```

`rehearse.py --help` describes the opt-in local runtime rehearsal. It uses disposable host and
Codex homes, an owned foreground backend, exact owned tmux targets and a local mock Responses
service. It never calls `ciao setup`, writes vendor trust hashes itself, or uses a subscription
model. Default shared-server reuse and standalone launches are checked separately. The isolated
TUI environment retains only `TMUX` and `TMUX_PANE` generated by its newly created tmux child,
not values borrowed from the caller: Codex uses these markers to recover missed resize events.
Stripping them can leave a corrupted chooser after rapid viewer attachment/detachment even
though the authenticated foreground status is correct.

Run from the host repository with a matching `cargo build --locked -p ciao-host -j1` after
Cargo test/Clippy artifact changes; the private identity initializer links that build's rlib.
On macOS, the default all-process Seatbelt fence can prevent the observer from executing
setuid system `ps`, which its existing process authentication requires. The explicit
`--allow-observer-network` option runs only the owned Ciao observer (including restarts and
its history children) outside that fence. It permits ordinary relay startup and process
inspection; it does not relax production authentication. Vendor TUIs/backend remain
loopback-fenced with fake credentials. Receipts explicitly disclaim all-process network
attestation in this mode.

```sh
python3 -B integrations/codex/terminal-status/rehearse.py \
  --ciao-binary "$PWD/target/debug/ciao" \
  --codex-binary /tmp/codex-terminal-candidate/codex \
  --persisted-side-chats --allow-observer-network --timeout 600
```

The persisted journey includes real TUI restart, saved-but-unloaded exclusion, cold route
recovery and a same-observer warm focus cycle. Route commits are asynchronous; enumeration
completion is not their barrier. The harness waits for the exact committed set and refuses
extra/wrong routes rather than using a fixed delay. A passing status/log journey is **not**
full qualification: actual cached-token refusal requires authenticated paired
`terminal.open(agent_route)` calls and fresh positive controls. Idle new-TUI recovery before
fresh hooks is reported separately and remains refused without sufficient current provenance.
Neither the script nor its receipts authorize installation or release.
