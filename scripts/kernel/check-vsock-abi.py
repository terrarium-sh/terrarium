#!/usr/bin/env python3
"""Check the fixed vsock device, the kernel endpoint set, and reviewed kernel-only buffer limits."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
SOCKET_PATCH = '0004-terra-socket-vsock.patch'
PATCH_NAMES = {
    '0001-x86-discard-unavailable-legacy-clockevent.patch',
    '0002-fuse-virtiofs-file-events.patch',
    SOCKET_PATCH,
}


def parse_constant(source, expression, description):
    declaration = re.search(expression, source, re.MULTILINE)
    if declaration is None:
        raise ValueError(f'Cannot verify {description}; rebuild matching vsock artifacts.')
    return int(declaration[1].replace('_', ''))


def validate_device_id(source):
    device_id = parse_constant(
        source, r'MmioTransport::new\(\s*[^,]+,\s*([0-9_]+),',
        'the frontend virtio device ID',
    )
    if device_id != 19:
        raise ValueError('Vsock frontend must use stock virtio device ID 19.')


def validate_kernel_config(source):
    for name in ('VSOCKETS', 'VIRTIO_VSOCKETS'):
        values = re.findall(rf'^(?:CONFIG_{name}=(\w+)|# CONFIG_{name} is not set)$',
                            source, re.MULTILINE)
        if not values or any(value != 'y' for value in values):
            raise ValueError(f'Guest kernels require built-in CONFIG_{name}=y.')


def validate_patch_series(patches):
    if set(patches) != PATCH_NAMES:
        raise ValueError('Active kernel patches must be exactly 0001, 0002 and 0004-terra-socket-vsock.patch.')


def validate_endpoints(kernel_source):
    endpoints = set()
    for declaration in re.findall(r'^\s*struct sockaddr_vm \w+ = \{([^}]+)\};',
                                  kernel_source, re.MULTILINE):
        cid = re.search(r'\.svm_cid\s*=\s*(\w+)', declaration)
        if cid is None:
            raise ValueError('Every kernel vsock endpoint must name its .svm_cid.')
        cid = cid[1]
        if '.svm_port = VMADDR_PORT_ANY' in declaration:
            if cid != 'TERRA_GUEST_CID':
                raise ValueError('Dynamic flow source ports require guest CID 3.')
            continue
        port = re.search(r'\.svm_port\s*=\s*(\w+)', declaration)
        if port is None:
            raise ValueError('Every kernel vsock endpoint must name its .svm_port.')
        endpoints.add((cid, port[1]))
    if endpoints != {('TERRA_HOST_CID', 'TERRA_TCP_PORT'), ('TERRA_HOST_CID', 'TERRA_UDP_PORT')}:
        raise ValueError('The kernel opens only dynamic per-socket streams to host TCP 6002 and UDP 6003.')


def validate_kernel_buffers(kernel_source):
    for name, expected in (('TERRA_TCP_SEGMENT_BYTES', 65535),
                           ('TERRA_TCP_SEND_BYTES', 49152),
                           ('TERRA_UDP_QUEUE_BYTES', 131072),
                           ('TERRA_UDP_QUEUED_DATAGRAMS', 48)):
        value = parse_constant(kernel_source, rf'^#define {name} ([0-9_]+)$', name)
        if value != expected:
            raise ValueError(f'{name} requires the reviewed limit of {expected}.')


def load_kernel_source(root):
    return '\n'.join((root / path).read_text() for path in (
        'kernel/overlay/include/linux/terra_abi.h',
        'kernel/overlay/include/linux/terra_socket.h',
        'kernel/overlay/net/terra/socket.c',
    ))


def check(root=ROOT):
    patches = {path.name for path in (root / 'kernel/patches').glob('*.patch')}
    validate_patch_series(patches)
    kernel_source = load_kernel_source(root)
    validate_kernel_buffers(kernel_source)
    common_config = (root / 'kernel/terra.config').read_text()
    for architecture in ('x86_64', 'aarch64'):
        validate_kernel_config(common_config + '\n' + (root / f'kernel/{architecture}.config').read_text())
    validate_device_id((root / 'components/vsock-frontend/src/transport.rs').read_text())
    validate_endpoints(kernel_source)


if __name__ == '__main__':
    try:
        check()
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
