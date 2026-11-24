# Linked computers

Ciao can explicitly introduce two computers so an agent on one can start Claude or native Codex
in a granted workspace on the other. It uses the daemons' existing Iroh identities and encrypted
transport. There is no account, public roster, SSH setup or shared private key.

On the phone, hold any host card and choose **Linked Computers**. Every other computer has a
row in each direction: who can start agents on this host, and where this host can start
agents. Tap a row and choose **Selected projects** or **All projects**, then **Allow**. All
projects includes projects added to the destination later. Both computers must be paired with
that phone and reachable while linking. Afterwards the phone can be offline, and changing the
projects only needs the destination.

Open the same row later to change projects in place or to **Remove Access**. Removing blocks
new requests and closes peer connections; existing agents continue under your control.
Narrowing the projects does the same for sessions in projects you removed. Each direction is
separate: removing one never removes the other. Unpairing the phone on the destination also
revokes incoming grants that phone introduced.

Hosts on 0.1.61 or earlier can add selected projects and remove access, but cannot edit a grant,
allow all projects or replace a stale link; the app says when an update is needed. A full
`ciao reset` removes incoming grants, outgoing links and start claims before discarding the
host identity; if that removal fails, the identity is retained and the reset reports an error.

## Use from an agent or terminal

All commands below emit JSON. Run them on the source computer, using the matching CLI and
daemon build. A host selector is its exact display name or an unambiguous endpoint-ID prefix.

```sh
ciao peers list
ciao peers workspaces --host 'Build Computer'
ciao peers start --host 'Build Computer' --workspace <workspace-id> --agent codex --request-id <unique-id>
ciao peers snapshot --host 'Build Computer' <session-id>
ciao peers send --host 'Build Computer' <session-id> --request-id <another-id> --prompt-file task.txt
ciao peers follow --host 'Build Computer' <session-id> --seconds 60
ciao peers interrupt --host 'Build Computer' <session-id> --request-id <another-id>
ciao peers stop --host 'Build Computer' <session-id> --request-id <another-id>
```

Any agent with shell access on the source can use these commands. Omit `--agent` for
managed Claude, or pass `--agent claude` explicitly. Both hosts need the new CLI/daemon
for Codex. A destination that supports the choice includes `codex` in the `agents`
array returned by `workspaces`. Using `--agent codex` against an older destination
returns `unsupported_peer_agent`.

Install the complete native Codex distribution on the destination, including the tool
executables shipped beside its binary. Sign in there as the user running Ciao. The
destination daemon uses its recorded Codex executable, its own PATH, or the user's
`~/.local/bin/codex`. Codex can use that user's eligible ChatGPT login. Each start
creates a fresh thread.
Use its returned Ciao session ID with send, follow, interrupt and stop. A phone can
open that conversation and answer approvals. Closing the phone or disconnecting the
source leaves it running. After a peer stop, snapshot, follow and send report
`session_stopped`. Retrying the same stop ID recovers the original receipt. After
terminal handback or a destination daemon restart, the peer run is unavailable.
Codex retains its ordinary written conversation history on the destination.

Calls to one computer share one encrypted connection, so each call after the first costs about
one network round trip instead of three. The source closes it after 20 seconds without a call. A
computer on Ciao 0.1.66 or earlier still gets one connection per call, so update both for the faster
path. If a connection fails after a request was sent, the command reports `outcome_unknown` (or
`connection_lost` for a read) and sends nothing again; retry with the same request ID.

`--prompt-file -` reads a bounded UTF-8 prompt from stdin. Keep prompts out of shell arguments.
A newly spawned worker may briefly answer `session_unavailable` until it registers; inspect
its snapshot before sending. A canonical command receipt distinguishes submission from
application. Tool approvals and questions are answered by the person through Ciao, not by
these peer commands. For the specified interval, `follow` prints the canonical snapshot as one
JSON line when it first reads it, and again only when it changes (soon after the change, at most
four a second). After each second with no change it prints a small heartbeat line instead:

```json
{"type":"heartbeat","session_id":"<session-id>","snapshot_epoch":3,"process_generation":2,"revision":41}
```

A heartbeat names the snapshot already printed and carries no conversation content. Snapshot
lines have no `type` field. The output is the same against a computer on Ciao 0.1.66 or earlier,
which this side polls once a second. An unavailable connection is reported as an error, never as
a heartbeat or a stopped agent.

Retry a lost start reply with the **same request ID, workspace and agent**. A recorded outcome is
returned; an interrupted launch claim returns `outcome_unknown` and is never blindly launched
again. Creating a new ID after an uncertain result may create another worker. Inspect the
destination from your phone first. Prompt/interrupt receipts retain the existing canonical
24-hour receipt policy; do not replay old commands as new turns.

For a phone-free explicit introduction, use `ciao peers list` on both computers, then run
`ciao peers grant --endpoint <source-id> --name <source-name> --workspace <destination-workspace-id>`
(repeat `--workspace`, or pass `--all`) on the destination. Save the returned public link JSON
to a file and run `ciao peers remember --file link.json` on the source; it replaces any older
link to that destination. Change the projects later with
`ciao peers update --endpoint <source-id> --workspace <id>` (or `--all`) on the destination.
The link is bound to the source endpoint's authenticated key; it is not a bearer credential.
Revocation is `ciao peers revoke <exact-source-endpoint-id>` on the destination.
`ciao peers forget <exact-destination-endpoint-id>` on the source drops only its local link and
does not revoke the destination's grant.

## Authority and limits

A grant authorizes the source computer's OS user, not a sandboxed individual agent. The
destination agent runs tools with the destination's existing credentials and permission
settings. Managed workers load the destination's user/project/local configuration, including
its installed integrations, native coding-agent prompt and browser opt-in; explicit saved session choices survive resume.
Daemon startup refreshes an already installed Ciao worker to the code shipped in that daemon,
so ordinary updates apply launch-policy fixes without reinstalling the vendor SDK or changing
the recorded Node/PATH. An absent managed installation remains absent.
Source-host settings and credentials are never copied. This is the same launch contract used
by the phone and local CLI, rather than a peers-only mode. A selected project chooses its working directory; it does not contain filesystem
or network access. Use an appropriate provider/OS sandbox when you need containment.

The peer protocol permits selected-workspace discovery, managed Claude and native Codex creation, and
snapshot/prompt/interrupt/stop for sessions created under that exact grant. It exposes no
terminal, arbitrary command/argv/environment API, other-session history, tool approval,
permission-mode change, file transfer, port forward, or peer-administration operation.
Grants are directional. New hosts, reverse links and further destinations require explicit
grants. No credentials or authority propagate through introductions. An agent's tool access
can still exercise other access its OS user already holds.

An all-projects grant covers every project the destination itself can resolve: Ciao-managed
session directories plus Git checkouts it discovers under home, including later ones. The
source can see all of their names. The source still names a project by its opaque ID, never by
a path.

Limits: 16 incoming and 16 outgoing peers, 32 selected projects per grant (or all), two live
workers per grant, and 256 total durable start records. Full stores refuse new work without dropping replay
protection. Revoking a grant removes its start metadata; a new grant has a fresh ID and no access
to the old grant's sessions. Project files are not synchronized. The source receives the selected session’s canonical
snapshots, including its conversation content; Ciao adds no transcript persistence on either
host. File/context transfer and Git coordination are explicit. Destination vendor/runtime gates
still apply.

Peer grants and start reservations live in the destination-owned private `peers.json`.
Native Codex outcomes use the adjacent private `peer-codex-receipts.json`. Older daemons
can still read the grants and replay an explicit refusal for a Codex reservation.
The files store public identities, scope, session IDs and lifecycle receipts. Prompt and timeline
bodies stay out of both files. The destination checks the peer's authenticated endpoint ID
before decoding a request and checks its current grant again before every effect.
