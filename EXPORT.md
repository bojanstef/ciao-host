# Maintaining this reviewed export

This tree is a source snapshot, not a second implementation. Ciao's private monorepo remains authoritative for host code, vendor pins and shared protocol fixtures. No monorepo Git history, app source, private documentation, operational tooling or credentials is included.

`EXPORT-MANIFEST.txt` lists every file in this snapshot. The maintainer separately retains the committed source revision, source-blob allowlist, final SHA-256 inventory, privacy substitutions and local validation record. That private review bundle is **not** part of the public tree.

## Refresh procedure (manual)

1. Choose one committed monorepo revision. Inspect worktree changes separately; never silently include them. Expand a reviewed allowlist into individual file paths and obtain their blobs from that revision, not from a recursive worktree copy. Reject symlinks, submodules and unexpected files.
2. Export only the Rust workspace and lockfile, host crate, both patched vendors and licenses, required protocol fixtures, the embedded integration sources, explicitly selected offline tests/generator and installer, and host-specific licensing material. The three embedded integration files are mandatory even for a build without tests.
3. Apply the separately reviewed privacy substitutions to comments and test data. In this snapshot they replace an operator crontab, personal display/workspace labels and private skill examples. The notification test vector keeps its public test key, nonce, algorithm and schema; its ciphertext is regenerated for the synthetic display label. No production logic, protocol schema, bound, capability, pin or relay gate is changed. The corresponding test expectations change together; coverage stays present.
4. Reapply the public README, media, notices renderer, pinned development toolchain and host-only Linux CI. Preserve both vendor `CIAO-PATCH.md` files. Those upstream-patch notes and some source comments refer to internal design records intentionally not exported; they are not public build dependencies. Never bring in the private packager, signing setup or live conformance factory to satisfy a reference.
5. Scan the entire resulting filesystem (not just Git-tracked files), decode any archives, inspect symlink targets and media, and review secret-scanner findings individually. Synthetic cryptographic vectors are intentional, not a reason to skip future findings in their files. Regenerate notices with `python3 scripts/host_notices.py`.
6. Run the README's checks **from the standalone tree**, with no private environment files or production relay credential. Keep build output and review evidence outside the publication tree. Record test counts, early-return/live skips, failures and missing platform evidence.
7. Re-scan and compare every file/hash to the approved inventory. Obtain explicit approval of the exact destination and contents before any public write. Start public history from this snapshot; never copy private history. Source publication is not binary release or website-deployment authority.

## Reconcile changes rather than fork the work

Review public patches, bring accepted code/fixture changes into the authoritative monorepo, test affected Rust and iOS consumers there, then make another reviewed export. Do not independently merge protocol evolution into this tree. Keep public-only packaging changes as a small reviewed overlay, not an automatic sync service.

The initial privacy-only fixture substitutions are recorded explicitly because those files are shared with the app. Reconcile them into the monorepo and its Swift expectations in a separately coordinated change before the next refresh, or retain the reviewed substitutions explicitly; never overwrite them with live-derived samples. No Swift validation is claimed by this host-only export.
