# iroh 1.0.2, vendored with one narrow patch

This is the `iroh` crate exactly as published at 1.0.2 (examples, tests, benches, and docs
dropped; nothing else touched) plus one addition in
`src/socket/remote_map/remote_state/path_watcher.rs`: `Path::close()` and
`Path::set_max_idle_timeout()` on the per-path snapshot item, forwarding to the `noq::Path`
handle the snapshot already holds for `stats()`.

Why: the daemon abandons a selected path whose sends have stopped being acknowledged while
another path is open (Spec 014 Class B, healed host-side — see
`docs/2026-09-02-connection-quality-lab.md`). iroh 1.0.2 exposes per-path statistics but no
per-path control, so the decision could be made and not acted on.

The pin stays `=1.0.2` (`[patch.crates-io]` in the workspace `Cargo.toml`); iroh-base,
iroh-relay, iroh-tickets, and noq are unpatched registry crates. Offer upstream as "expose
per-path close and idle timeout on `PathList` items"; when a release carries it, delete this
directory and the patch entry and bump the pin.

Reproduce: `cp -R ~/.cargo/registry/src/*/iroh-1.0.2 vendor/iroh`, delete `examples tests
docs benches`, strip the `[[example]]` tables from `Cargo.toml`, apply the `Path` impl
addition, keep this file.
