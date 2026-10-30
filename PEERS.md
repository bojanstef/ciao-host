# Linked computers

Ciao can explicitly introduce two computers so an agent on one can start a Ciao-managed
Claude session on the other. It uses the daemons' existing Iroh identities and encrypted
transport. There is no account, public roster, SSH setup or shared private key.

On the phone, hold the destination's host card and choose **Linked Computers**. Choose the
source computer and destination projects, then confirm **Allow Access**. Both computers must
already be paired with that phone and reachable during setup. After setup, the phone can be
offline. Older hosts refuse the new administration stream and need an update.

The destination's Linked Computers screen lists incoming grants and can revoke them. Revoking
blocks new requests and closes peer connections; existing agents continue under your control.
Unpairing the phone on the destination also revokes incoming grants that phone introduced.
The source may retain a stale introduction, which the destination will refuse. A full `ciao reset`
removes incoming grants, outgoing links and start claims before discarding the host identity;
if that removal fails, the identity is retained and the reset reports an error.

## Use from an agent or terminal

All commands below emit JSON. Run them on the source computer, using the matching CLI and
daemon build. A host selector is its exact display name or an unambiguous endpoint-ID prefix.

```sh
ciao peers list
ciao peers workspaces --host 'Build Computer'
ciao peers start --host 'Build Computer' --workspace <workspace-id> --request-id <unique-id>
ciao peers snapshot --host 'Build Computer' <session-id>
ciao peers send --host 'Build Computer' <session-id> --request-id <another-id> --prompt-file task.txt
ciao peers follow --host 'Build Computer' <session-id> --seconds 60
ciao peers interrupt --host 'Build Computer' <session-id> --request-id <another-id>
ciao peers stop --host 'Build Computer' <session-id> --request-id <another-id>
```

`--prompt-file -` reads a bounded UTF-8 prompt from stdin. Keep prompts out of shell arguments.
A newly spawned worker may briefly answer `session_unavailable` until it registers; inspect
its snapshot before sending. A canonical command receipt distinguishes submission from
application. Tool approvals and questions are answered by the person through Ciao, not by
these peer commands. `follow` polls canonical snapshots once per second for the specified
interval; an unavailable connection is reported as an error, not as a stopped agent.

Retry a lost start reply with the **same request ID and workspace**. A recorded outcome is
returned; an interrupted launch claim returns `outcome_unknown` and is never blindly launched
again. Creating a new ID after an uncertain result may create another worker. Inspect the
destination from your phone first. Prompt/interrupt receipts retain the existing canonical
24-hour receipt policy; do not replay old commands as new turns.

For a phone-free explicit introduction, use `ciao peers list` on both computers, then run
`ciao peers grant --endpoint <source-id> --name <source-name> --workspace <destination-workspace-id>`
on the destination. Save the returned public link JSON to a file and run
`ciao peers remember --file link.json` on the source. The link is bound to the source endpoint's
authenticated key; it is not a bearer credential. Local revocation is
`ciao peers revoke <exact-source-endpoint-id>` on the destination. Removing only the source's
local introduction does not revoke the destination's grant.

## Authority and limits

A grant authorizes the source computer's OS user, not a sandboxed individual agent. The
destination agent runs tools with the destination's existing credentials and permission
settings. A selected project chooses its working directory; it does not contain filesystem
or network access. Use an appropriate provider/OS sandbox when you need containment.

The peer protocol permits selected-workspace discovery, managed Claude creation, and
snapshot/prompt/interrupt/stop for sessions created under that exact grant. It exposes no
terminal, arbitrary command/argv/environment API, other-session history, tool approval,
permission-mode change, file transfer, port forward, or peer-administration operation.
Grants are directional. New hosts, reverse links and further destinations require explicit
grants. No credentials or authority propagate through introductions. An agent's tool access
can still exercise other access its OS user already holds.

Limits: 16 incoming and 16 outgoing peers, 32 selected projects per grant, two live workers per
grant, and 256 total durable start records. Full stores refuse new work without dropping replay
protection. Revoking a grant removes its start metadata; a new grant has a fresh ID and no access
to the old grant's sessions. Project files are not synchronized. The source receives the selected session’s canonical
snapshots, including its conversation content; Ciao adds no transcript persistence on either
host. File/context transfer and Git coordination are explicit. Destination vendor/runtime gates
still apply.

Peer metadata lives in the destination-owned private `peers.json`, separate from paired phones.
It contains grants, public identities, scope, session IDs and start outcomes, never prompt or
timeline bodies. The authenticated peer's endpoint ID is checked before a request is decoded
and its current grant is checked again before every effect.
