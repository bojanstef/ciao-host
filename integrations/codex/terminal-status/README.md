# Local Codex terminal identity, version 1

Codex's standalone TUI can authenticate its hooks through process ancestry. A shared
app-server cannot identify a terminal that way: several TUIs share one backend, and a
thread subscription can outlive the conversation displayed by its TUI. Attached observation
therefore needs an independent, kernel-authenticated terminal identity.

This interface requires the accompanying Codex TUI patch; stock Codex 0.166.0 does not
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
3. Still names the same TUI incarnation and generation when a route or takeover is used.

Missing, oversized, malformed, stale, remote, disconnected or ambiguous evidence is refused.
Unrecognized vocabulary is tallied without recording values or content. Neither cwd, argv
resume arguments, titles, timestamps, a shared socket nor a rollout holder alone establishes
this association. Shared-backend hooks remain read-only observations. The backend is never
a terminal exit target. Foreign rollout ownership continues to refuse adoption, even after
a TUI exits, until the vendor actually releases it.

Validation must cover standalone and shared mode, two TUIs, same-thread ambiguity, thread
switches and history, idle resume before hooks, PID reuse, backend and Ciao restarts,
disconnects, foreign writers, and refusal to target the shared backend during takeover.
