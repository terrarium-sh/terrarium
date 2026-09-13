#!/usr/bin/env python3
"""Export or import a kernel paired with its source/configuration identity."""

import gzip
import hashlib
import io
from pathlib import Path
import sys
import tarfile


MEMBERS = ('vmlinux.gz', 'kernel.config', 'kernel.inputs')


def export_kernel(kernel, config, inputs, destination):
    output = Path(destination)
    temporary = output.with_suffix('.tmp')
    with temporary.open('wb') as raw:
        with gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as archive:
                for name, source in zip(MEMBERS, (kernel, config, inputs)):
                    data = Path(source).read_bytes()
                    entry = tarfile.TarInfo(name)
                    entry.size = len(data)
                    entry.mode = 0o644
                    archive.addfile(entry, io.BytesIO(data))
    temporary.replace(output)


def import_kernel(source, checksum, inputs, kernel, config):
    data = Path(source).read_bytes()
    if hashlib.sha256(data).hexdigest() != checksum:
        raise ValueError('kernel archive SHA-256 mismatch')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        entries = archive.getmembers()
        if len(entries) != len(MEMBERS) or {entry.name for entry in entries} != set(MEMBERS):
            raise ValueError('unexpected kernel archive members')
        if any(not entry.isfile() for entry in entries):
            raise ValueError('kernel archive members must be regular files')
        contents = {entry.name: archive.extractfile(entry).read() for entry in entries}
    if contents['kernel.inputs'] != Path(inputs).read_bytes():
        raise ValueError('kernel archive does not match this architecture, source pin, and config')
    image = gzip.decompress(contents['vmlinux.gz'])
    for destination, payload in ((kernel, image), (config, contents['kernel.config']),
                                 (str(kernel) + '.gz', contents['vmlinux.gz'])):
        output = Path(destination)
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_suffix(output.suffix + '.tmp')
        temporary.write_bytes(payload)
        temporary.replace(output)


if __name__ == '__main__':
    action, *arguments = sys.argv[1:]
    if action == 'export':
        export_kernel(*arguments)
    elif action == 'import':
        import_kernel(*arguments)
    else:
        raise SystemExit('expected export or import')
