#!/usr/bin/env python3
"""Check the fixed vsock device, endpoints, and application ABI."""

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
    factors = declaration[1].replace('_', '').split('*')
    value = 1
    for factor in factors:
        value *= int(factor.strip(), 0 if factor.strip().startswith('0x') else 10)
    return value


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


def validate_socket_version(source, kernel_source):
    version = parse_constant(source, r'^pub const VERSION: u16 = ([0-9a-fA-F_x]+);$',
                             'the socket ABI version')
    kernel_version = parse_constant(kernel_source, r'^#define TERRA_SOCKET_VERSION ([0-9a-fA-F_x]+)$',
                                    'the kernel socket ABI version')
    if kernel_version != version:
        raise ValueError('Rust and kernel socket ABI versions differ; rebuild matching artifacts.')


def validate_application_abi(source, kernel_source):
    version = parse_constant(source, r'^pub const VERSION: u16 = ([0-9a-fA-F_x]+);$',
                             'the network frame version')
    kernel_version = parse_constant(kernel_source, r'^#define TERRA_NETWORK_VERSION ([0-9a-fA-F_x]+)$',
                                    'the kernel network frame version')
    if kernel_version != version:
        raise ValueError('Rust and kernel network frame ABI versions differ; rebuild matching artifacts.')
    rust_header = parse_constant(source, r'^pub const HEADER_BYTES: usize = ([0-9_]+);$', 'HEADER_BYTES')
    kernel_header = parse_constant(kernel_source, r'^#define TERRA_HEADER_BYTES ([0-9_]+)$',
                                   'TERRA_HEADER_BYTES')
    if rust_header != 8 or kernel_header != 8:
        raise ValueError('Network frames must use the fixed 8-byte header.')
    for name, value in (('TCP_OPEN', 0x01), ('UDP_OPEN', 0x02), ('UDP_SEND', 0x03),
                        ('TCP_OPENED', 0x101), ('UDP_OPENED', 0x102),
                        ('UDP_DATAGRAM', 0x103), ('UDP_ERROR', 0x104)):
        kernel_value = parse_constant(kernel_source, rf'^#define TERRA_OP_{name} (0x[0-9a-fA-F]+)$',
                                      f'kernel opcode {name}')
        rust_name = ''.join(part.capitalize() for part in name.split('_'))
        rust_value = parse_constant(source, rf'^\s+{rust_name} = (0x[0-9a-fA-F]+),$', f'opcode {rust_name}')
        if kernel_value != value or rust_value != value:
            raise ValueError(f'Network opcode {name} must be {value:#x} in Rust and the kernel.')


def validate_endpoints(protocol_source, kernel_source):
    for name, expected in (('HOST_CID', 2), ('GUEST_CID', 3), ('AGENT_PORT', 6000),
                           ('CONTROL_PORT', 6001), ('TCP_PORT', 6002), ('UDP_PORT', 6003),
                           ('PUBLICATION_PORT', 6004)):
        value = parse_constant(protocol_source, rf'^pub const {name}: u32 = ([0-9_]+);$', name)
        if value != expected:
            raise ValueError(f'Fixed vsock {name} must be {expected}.')
    for name, expected in (('TERRA_TCP_PORT', 6002), ('TERRA_UDP_PORT', 6003)):
        if parse_constant(kernel_source, rf'^#define {name} ([0-9_]+)$', name) != expected:
            raise ValueError(f'Kernel {name} must be {expected}.')
    endpoints = set()
    for declaration in re.findall(r'^\s*struct sockaddr_vm \w+ = \{([^}]+)\};',
                                  kernel_source, re.MULTILINE):
        cid = parse_constant(declaration, r'\.svm_cid\s*=\s*([0-9_]+)', 'kernel CID')
        if '.svm_port = VMADDR_PORT_ANY' in declaration:
            if cid != 3:
                raise ValueError('Dynamic flow source ports require guest CID 3.')
            continue
        port = re.search(r'\.svm_port\s*=\s*(\w+)', declaration)[1]
        endpoints.add((cid, port))
    if endpoints != {(2, 'TERRA_TCP_PORT'), (2, 'TERRA_UDP_PORT')}:
        raise ValueError('The kernel opens only dynamic per-socket streams to host TCP 6002 and UDP 6003.')


def validate_kernel_buffers(kernel_source):
    for name, expected in (('TERRA_TCP_SEGMENT_BYTES', 65535),
                           ('TERRA_TCP_RECEIVE_BYTES', 81920),
                           ('TERRA_TCP_SEND_BYTES', 49152),
                           ('TERRA_UDP_QUEUE_BYTES', 65536),
                           ('TERRA_UDP_QUEUED_DATAGRAMS', 48)):
        value = parse_constant(kernel_source, rf'^#define {name} ([0-9_]+)$', name)
        if value != expected:
            raise ValueError(f'{name} requires the reviewed limit of {expected}.')


def load_kernel_source(root):
    return '\n'.join((root / path).read_text() for path in (
        'kernel/overlay/include/linux/terra_socket.h',
        'kernel/overlay/net/terra/socket.c',
    ))


def check(root=ROOT):
    patches = {path.name: path.read_text() for path in (root / 'kernel/patches').glob('*.patch')}
    validate_patch_series(patches)
    kernel_source = load_kernel_source(root)
    validate_kernel_buffers(kernel_source)
    common_config = (root / 'kernel/terra.config').read_text()
    for architecture in ('x86_64', 'aarch64'):
        validate_kernel_config(common_config + '\n' + (root / f'kernel/{architecture}.config').read_text())
    validate_device_id((root / 'components/vsock-frontend/src/transport.rs').read_text())
    validate_socket_version((root / 'crates/terra-protocol/src/socket.rs').read_text(), kernel_source)
    validate_application_abi((root / 'crates/terra-protocol/src/application.rs').read_text(), kernel_source)
    validate_endpoints((root / 'crates/terra-protocol/src/vsock.rs').read_text(), kernel_source)


if __name__ == '__main__':
    try:
        check()
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
