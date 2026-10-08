#!/usr/bin/env python3
"""Reject kernel builds that silently drop a requested feature or hardening setting."""

from pathlib import Path
import sys


def settings(path):
    values = {}
    for line in Path(path).read_text().splitlines():
        if line.startswith('CONFIG_'):
            name, value = line.split('=', 1)
            values[name] = value
        elif line.startswith('# CONFIG_') and line.endswith(' is not set'):
            values[line[2:-11]] = 'n'
    return values


def validate(config, fragments):
    resolved = settings(config)
    requested = {}
    for fragment in fragments:
        requested.update(settings(fragment))
    errors = [f'{name}: wanted {value}, got {resolved.get(name, "n")}'
              for name, value in requested.items() if resolved.get(name, 'n') != value]
    if errors:
        raise ValueError('\n'.join(errors))


if __name__ == '__main__':
    try:
        validate(sys.argv[1], sys.argv[2:])
    except ValueError as error:
        raise SystemExit(str(error)) from error
