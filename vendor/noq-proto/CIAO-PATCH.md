# noq-proto 1.0.1, vendored with one narrow patch

`noq-proto` exactly as published at 1.0.1 — the version iroh 1.0.2 resolves to — with benches,
examples, tests, and fuzz targets dropped, plus one field: `PathStats::pto_count`, filled in
`Connection::path_stats()` from the per-path loss-detection state that already exists.

Why: the daemon abandons a selected path whose sends are no longer being answered while another
path is open (see `docs/2026-09-02-connection-quality-lab.md`). Under a one-way blackhole the
published per-path statistics cannot show that: with no acknowledgement to compare against,
QUIC never declares a packet lost, `cwnd` never moves, and ACK-frame counts are attributed to the
path a frame arrived on rather than the path it acknowledges. The probe-timeout counter is the
value the transport itself backs off on, and any acknowledgement of the path resets it.

The pin is unchanged; wired through `[patch.crates-io]` in the workspace `Cargo.toml`. Offer
upstream as "expose pto_count in PathStats"; delete this directory when a release carries it.

Reproduce: `cp -R ~/.cargo/registry/src/*/noq-proto-1.0.1 vendor/noq-proto`, delete `benches
examples tests fuzz proptest-regressions`, strip the `[[bench]]` table from `Cargo.toml`, add the
field and the assignment, keep this file.
