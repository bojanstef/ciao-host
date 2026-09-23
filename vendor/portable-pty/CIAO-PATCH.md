# portable-pty 0.9.0, vendored with one narrow patch

This is the `portable-pty` crate exactly as published at 0.9.0 (examples dropped, its `[[example]]`
tables with them; nothing else touched) minus one behaviour in `src/unix.rs`: `UnixMasterWriter`
no longer implements `Drop`. Upstream's drop sends `\n` followed by the tty's EOF character into
the pty — a courtesy so a shell reading the slave exits when the writer goes away.

Why: Ciao closes provider *attach clients* (tmux, herdr), not shells, and a client that has put its
terminal into raw mode does not read those two bytes as end-of-file. It reads a Ctrl-J and a Ctrl-D
typed at it and forwards both to the focused pane, where a shell then really does exit. That
destroyed tmux sessions on cleanup under load (`Release artifacts` red on `main` from 2026-09-22;
the pane's byte tap read `0a 04` at the millisecond cleanup began) and was the herdr composer
newline of 2026-07-30, kitty-encoded by herdr on the way through and attributed to herdr's client
for two months. Ciao ends children with its own signal ladder and must never type into a terminal it
is closing. `pty::tests::cleanup_types_nothing_into_the_terminal` is the fence: red against the
registry crate (`[10, 4]` captured), green against this one.

The pin stays `0.9.0` (`[patch.crates-io]` in the workspace `Cargo.toml`); `filedescriptor` and the
rest of its dependency tree are unpatched registry crates. Offer upstream as "make the EOT sent on
`UnixMasterWriter` drop opt-in, or provide a writer that does not send it" (wezterm/wezterm,
`pty/`); when a release carries either, delete this directory and the patch entry and bump the pin.

Reproduce: `cp -R ~/.cargo/registry/src/*/portable-pty-0.9.0 vendor/portable-pty`, delete
`examples .cargo-ok .cargo_vcs_info.json Cargo.toml.orig Cargo.lock`, strip the `[[example]]`
tables from `Cargo.toml`, remove `impl Drop for UnixMasterWriter` and replace the struct's doc
comment with the one now in `src/unix.rs`, keep this file.
