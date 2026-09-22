#!/usr/bin/env python3
"""Check that component WIT dependencies link to the shared definitions."""
from pathlib import Path

root = Path(__file__).resolve().parent.parent
shared = root / 'components/wit'
links = [root / 'components/block/wit/host.wit']
for component in ('vmm', 'mmio', 'interrupt-controller'):
    links.extend((root / f'components/{component}/wit').glob('*.wit'))
for deps in [shared / 'terra/deps', *root.glob('components/*/wit/deps')]:
    links.extend(deps.iterdir())
for link in links:
    if not link.is_symlink():
        raise SystemExit(
            f'{link.relative_to(root)} must be a Git symlink to components/wit/; '
            'enable core.symlinks before checkout (Windows also requires symlink privileges)'
        )
    target = link.resolve(strict=True)
    if not target.is_relative_to(shared):
        raise SystemExit(f'{link.relative_to(root)} points outside components/wit/')
print(f'Validated {len(links)} shared WIT links')
