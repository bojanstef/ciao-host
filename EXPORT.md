# Source ownership and publication boundaries

This repository is the authoritative home for the Ciao host, embedded integrations,
transport patches, dependency pins and language-neutral protocol fixtures. Develop host
changes here. Do not maintain a second host implementation or refresh this tree from a
private repository sweep.

The closed-source app consumes an explicitly pinned host revision. A change to an encoded
contract must update its producer, shared fixture and all affected consumers together,
then pass Rust and app-side checks before the consumer pin advances. Fixtures must remain
synthetic. Keep the fixtures and the code that owns protocol bounds here; never maintain a
second fixture tree in the app repository.

Public changes must be reviewed before pushing: inspect the exact paths and diff, check for
credentials and private data (including comments, test samples and media), and run the
README's checks. Do not post raw operational logs, personal host/session names, transcripts,
endpoint tickets, signing material or relay credentials. Synthetic cryptographic vectors
still require individual review when a scanner flags them; do not suppress whole files.

The iOS app, private design/acceptance records, operational tooling and production
packaging/signing credentials remain private. Their references in comments are not public
build dependencies and are not permission to copy those files here. A source push does not
authorize a binary release, deployment, or a change to production relay access.

## Origin of the public history

The initial public root commit `f1cc982f768c7791fc82094562cbb34ee90b474c` was a
reviewed, host-only snapshot with fresh history. `EXPORT-MANIFEST.txt` records that initial
224-file snapshot, not an evolving allowlist or a current checksum claim. The maintainer
retains its provenance and privacy review privately. No private Git history was imported.
The earlier manual-export workflow is superseded by repository ownership and pinned
consumption; the initial manifest and commit remain available as historical evidence.
