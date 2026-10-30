# iroh 1.0.2, vendored with two narrow patches

This is the `iroh` crate exactly as published at 1.0.2 (examples, tests, benches, and docs
dropped; nothing else touched) plus two changes.

## 1. Per-path close and idle timeout

An addition in `src/socket/remote_map/remote_state/path_watcher.rs`: `Path::close()` and
`Path::set_max_idle_timeout()` on the per-path snapshot item, forwarding to the `noq::Path`
handle the snapshot already holds for `stats()`.

Why: the daemon abandons a selected path whose sends have stopped being acknowledged while
another path is open (Spec 014 Class B, healed host-side — see
`docs/2026-09-02-connection-quality-lab.md`). iroh 1.0.2 exposes per-path statistics but no
per-path control, so the decision could be made and not acted on.

Offer upstream as "expose per-path close and idle timeout on `PathList` items".

## 2. Backport of the GHSA-7cq4-mhxw-xw78 fix (iroh 1.1.0)

`RelayTransport::poll_recv` in `src/socket/transports/relay.rs` drops a relay datagram batch
whose `segment_size` exceeds the receive buffer, with a warning, instead of leaving it as the
pending item forever. Before the fix, `buf_out.len() / segment_size` was 0, `take_segments(0)`
returned nothing, and every later poll delivered a zero-length datagram from the same item: any
peer that knew the endpoint id and could reach its relay could stop all relay-inbound traffic
and pin a core until restart ([advisory](https://github.com/n0-computer/iroh/security/advisories/GHSA-7cq4-mhxw-xw78),
High; affects iroh 0.91.0 through 1.0.3). The change and its regression test,
`progress_is_made_for_large_segment_size_datagram_batch`, are copied from iroh 1.1.0 unchanged.
The unrelated `Display` impl that release added to `RelayTransport` was left out.

The test cannot run from the workspace (`iroh` is not a member, so Cargo refuses its
dev-dependencies). Run it from a standalone copy: `cp -R vendor/iroh <tmp>/iroh`, copy in
`Cargo.lock` and `rust-toolchain.toml`, append an empty `[workspace]` table to the copy's
`Cargo.toml`, then `cargo test --lib socket::transports::relay`. It failed against 1.0.2 and
passed with the change (2026-10-28).

The phone runs the same transport through `iroh-ffi`, which this backport does not reach.

## Pin and removal

The pin stays `=1.0.2` (`[patch.crates-io]` in the workspace `Cargo.toml`); iroh-base,
iroh-relay, iroh-tickets, and noq are unpatched registry crates. Patch 2 retires when the pin
reaches 1.1.0 or later. Delete this directory and the patch entry when a release also carries
patch 1.

Reproduce: `cp -R ~/.cargo/registry/src/*/iroh-1.0.2 vendor/iroh`, delete `examples tests
docs benches`, strip the `[[example]]` tables from `Cargo.toml`, apply the `Path` impl
addition, apply the `poll_recv` change and its test from `iroh-1.1.0/src/socket/transports/relay.rs`,
keep this file.
