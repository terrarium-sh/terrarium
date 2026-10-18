#!/usr/bin/env python3
"""Compile shipped socket wrapper and transport credit paths without a VM."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
PATCH = ROOT / 'kernel/patches/0004-terra-socket-vsock.patch'
TESTS = Path(__file__).resolve().parent / 'vsock-tests'


def read_overlay_source(name: str) -> str:
    return (ROOT / 'kernel/overlay' / name).read_text()


def declaration(source: str, expression: str) -> str:
    match = re.search(expression, source, re.MULTILINE)
    if match is None:
        raise ValueError(expression)
    begin = source.index('{', match.start())
    depth = 1
    end = begin + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


def patched_source(name: str) -> str:
    selected = False
    lines = []
    for line in PATCH.read_text().splitlines():
        if line.startswith('+++ '):
            selected = line == f'+++ b/{name}'
        elif selected and line.startswith((' ', '+')):
            lines.append(line[1:])
    if not lines:
        raise ValueError(f'missing {name} in patch')
    return '\n'.join(lines)


def transport_credit_source(source: str) -> str:
    # Our credit change lives inside an upstream function the patch modifies; a helper would grow the patch.
    dequeue = declaration(source, r'^static ssize_t\nvirtio_transport_stream_do_dequeue\(')
    snapshot_begin = dequeue.index('\tspin_lock_bh(&vvs->tx_lock);')
    snapshot_end = dequeue.index('\tspin_lock_bh(&vvs->rx_lock);', snapshot_begin)
    notification_begin = dequeue.index('\tfwd_cnt_delta =')
    notification_end = dequeue.index('\n\treturn total;', notification_begin)
    return (
        declaration(source, r'^static void virtio_transport_dec_rx_pkt\(') + '\n'
        + declaration(source, r'^void virtio_transport_inc_tx_pkt\(') + '\n'
        + 'static void check_dequeue_credit(struct vsock_sock *vsk) {\n'
        + 'struct virtio_vsock_sock *vvs=vsk->trans;u32 fwd_cnt_delta,receive_window,peer_receive_window;\n'
        + 'bool low_rx_bytes;int receive_low_water;\n'
        + dequeue[snapshot_begin:snapshot_end]
        + '\tspin_lock_bh(&vvs->rx_lock);\n'
        + dequeue[notification_begin:notification_end] + '\n}\n'
        + declaration(source, r'^static bool virtio_transport_space_update\(')
    )


def transport_receive_source(source: str, connection: str) -> str:
    return ('\n'.join(declaration(source, rf'^(?:static )?ssize_t\n{name}\(') for name in (
        'virtio_transport_stream_do_peek', 'virtio_transport_stream_do_dequeue',
        'virtio_transport_stream_dequeue'))
        + '\n' + declaration(connection, r'^static int vsock_connectible_wait_data\(')
        + '\n' + declaration(connection, r'^static int vsock_set_peek_off\('))


def udp_definitions(source: str) -> str:
    names = ('TERRA_UDP_MAX_SEGMENTS', 'TERRA_UDP_SEGMENT_FIELD_BYTES', 'TERRA_UDP_CARRIER_BYTES',
             'TERRA_UDP_RUN_BYTES', 'TERRA_UDP_QUEUE_BYTES', 'TERRA_UDP_QUEUED_DATAGRAMS')
    definitions = [re.search(rf'^#define {name}\b(?:.*\\\n)*.*$', source, re.MULTILINE)[0] for name in names]
    control_block = re.search(r'^struct terra_datagram_cb \{.*?^#define TERRA_DATAGRAM_CB\(skb\)[^\n]*',
                              source, re.MULTILINE | re.DOTALL)[0]
    return '\n'.join(definitions) + '\n' + control_block + '\n'


def tcp_info_source(source: str) -> str:
    return (
        re.search(r'^#define TERRA_TCP_SEGMENT_BYTES [0-9]+$', source, re.MULTILINE)[0] + '\n'
        + declaration(source, r'^static bool terra_udp_option\(') + '\n'
        + declaration(source, r'^static bool terra_keepalive_option\(') + '\n'
        + declaration(source, r'^static int terra_getsockopt\(') + '\n'
        + declaration(source, r'^static int terra_send_stream\(') + '\n'
    )


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-directory', type=Path, help='check wrapper socket.c before patch export')
    args = parser.parse_args()
    source = (args.source_directory / 'socket.c').read_text() if args.source_directory \
        else read_overlay_source('net/terra/socket.c')
    if 'terra_network_' in source or 'TERRA_HELPER' in source:
        raise ValueError('The kernel socket wrapper must not carry the removed shared dispatcher or helper relay.')
    transport = patched_source('net/vmw_vsock/virtio_transport_common.c')
    request_credit = declaration(transport, r'^int virtio_transport_send_credit_request\(')
    functions = request_credit + '\n' + '\n'.join(declaration(source, rf'^static [^\n]*\b{name}\(') for name in (
        'terra_decode_error', 'terra_encode_peer', 'terra_decode_peer', 'terra_canonical_peer',
        'terra_peer_equal', 'terra_validate_opened', 'terra_open_timeout', 'terra_frame_header',
        'terra_datagram_bytes', 'terra_datagram_segment', 'terra_udp_queue_admits', 'terra_discard_udp_bytes',
        'terra_receive_udp_datagram', 'terra_resume_udp', 'terra_consume_datagram', 'terra_receive_coalesced',
        'terra_receive_udp_frame', 'terra_udp_writable', 'terra_udp_control', 'terra_send_udp',
        'terra_track_tcp_close', 'terra_setup_stream', 'terra_socket_poll', 'terra_set_peek_off', 'terra_listen',
        'terra_recv_stream', 'terra_recv_error_queue', 'terra_recv_native_datagram', 'terra_udp_receive_ready',
        'terra_deliver_datagram', 'terra_udp_send_segment', 'terra_apply_option', 'terra_connect_locked'))
    connection = patched_source('net/vmw_vsock/af_vsock.c')
    release_functions = '\n'.join(declaration(source, rf'^static [^\n]*\b{name}\([^;\n]*\)\n') for name in (
        'terra_resume_udp', 'terra_stream_callback', 'terra_restore_stream_callbacks', 'terra_detach_stream',
        'terra_release_socket'))
    programs = (
        ('socket-checks.c', udp_definitions(source) + functions, ['-Wno-unused-function', '-Wno-sign-compare']),
        ('tcp-info-checks.c', tcp_info_source(source), ['-Wno-sign-compare']),
        ('credit-checks.c', transport_credit_source(transport) + transport_receive_source(transport, connection),
         ['-Wno-sign-compare']),
        ('release-checks.c', release_functions, []),
    )
    with tempfile.TemporaryDirectory(prefix='terra-kernel-vsock-') as temporary:
        directory = Path(temporary)
        executable = directory / 'checks'
        for checks, extracted, warnings in programs:
            (directory / 'extracted.c').write_text(extracted)
            subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', *warnings, '-fsanitize=address,undefined',
                            '-g', f'-I{directory}', f'-I{TESTS}', str(TESTS / checks), '-o', str(executable)],
                           check=True)
            subprocess.run([str(executable)], check=True, env={**os.environ, 'ASAN_OPTIONS': 'detect_leaks=0'})
    print('kernel opening, TCP peek/discard/TCP_INFO, UDP controls/GSO/GRO/atomic backpressure, transport credit, and callback teardown checks passed')


if __name__ == '__main__':
    main()
