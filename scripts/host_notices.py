#!/usr/bin/env python3
"""Render the locked host dependency inventory, not a legal-compliance verdict."""
import argparse
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    metadata = json.loads(subprocess.check_output(
        ['cargo', 'metadata', '--locked', '--format-version', '1'], cwd=ROOT
    ))
    workspace = set(metadata['workspace_members'])
    packages = sorted(
        (p for p in metadata['packages'] if p['id'] not in workspace),
        key=lambda p: (p['name'], p['version']),
    )
    assert packages, 'no dependency inventory was produced'
    missing = [p['name'] for p in packages if not p.get('license')]
    if missing:
        raise SystemExit('Missing license metadata: ' + ', '.join(missing))
    lines = [
        '# Third-party notices', '',
        'Ciao host code is MIT OR Apache-2.0; dependencies retain their own licenses.',
        'Generated from `cargo metadata --locked` by `python3 scripts/host_notices.py`.',
        'This inventory includes transitive, development and target-specific dependencies;',
        'it does not imply that every entry is linked on every platform.', '',
        '## Vendored source', '',
        '- Iroh 1.0.2: MIT OR Apache-2.0, plus BSD-3-Clause notices for Tailscale-derived',
        '  socket code. All three license files are in `vendor/iroh/`.',
        '- noq-proto 1.0.1: MIT OR Apache-2.0; license files are in `vendor/noq-proto/`.',
        '- Each `CIAO-PATCH.md` records the local change and when to remove it.', '',
        'Registry packages are fetched by Cargo, not vendored here. Preserve their copyright',
        'and license texts when redistributing them or binaries; this table does not replace',
        'those obligations (including MPL-2.0 source availability where applicable).', '',
        '## Separately installed agent software', '',
        'The Claude Agent SDK and its bundled CLI are proprietary and are NOT included.',
        '`ciao agent install claude` fetches them from npm on the user\'s machine; their use',
        'is subject to Anthropic\'s terms. Codex and Pi are also installed separately.',
        'Only Ciao-authored integration code and protocol descriptions are included here.', '',
        '## Locked Rust dependency inventory', '',
        '| Crate | Version | License |', '|---|---|---|',
    ]
    lines.extend(f"| {p['name']} | {p['version']} | {p['license']} |" for p in packages)
    content = '\n'.join(lines) + '\n'
    dest = ROOT / 'THIRD-PARTY-NOTICES.md'
    if args.check:
        if not dest.is_file() or dest.read_text() != content:
            raise SystemExit('THIRD-PARTY-NOTICES.md is stale; run scripts/host_notices.py')
    else:
        dest.write_text(content)
    print(f'{len(packages)} dependency entries; notices {"current" if args.check else "written"}.')


if __name__ == '__main__':
    main()
