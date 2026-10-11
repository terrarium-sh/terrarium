#include "tcp-info-stubs.h"
#include "extracted.c"
static int check_tcp_send(struct socket *socket, struct msghdr *message, size_t length) {
    return terra_send_stream(terra_socket_state(socket), socket, message, length);
}

int main(void) {
    struct virtio_vsock_sock transport = {.buf_alloc = 81920, .peer_buf_alloc = 49152};
    struct vsock_sock carrier = {.trans = &transport};
    struct sock sk = {0};
    outer = &sk;
    struct proto_ops operations = {.sendmsg = carrier_send};
    struct proto_ops native = {.sendmsg = native_send, .getsockopt = native_info};
    struct socket stream = {.sk = &carrier.sk, .type = SOCK_STREAM, .ops = &operations};
    struct terra_tsi_socket state = {.sk = &sk,
                                     .mode = TERRA_SOCKET_EXTERNAL,
                                     .connected = true,
                                     .stream = &stream,
                                     .native_ops = &native};
    struct socket socket = {.sk = &sk, .type = SOCK_STREAM};
    sk.sk_user_data = &state;
    struct tcp_info information;
    int length = sizeof(information);
    assert(!terra_getsockopt(&socket, SOL_TCP, TCP_INFO, (char *)&information, &length));
    assert(length == (int)sizeof(information) && information.tcpi_snd_wnd == 49152 &&
           information.tcpi_bytes_acked == 1);
    assert(information.tcpi_snd_mss == UINT16_MAX && information.tcpi_rcv_mss == UINT16_MAX &&
           information.tcpi_advmss == UINT16_MAX);
    sk.tcp.rx_opt.user_mss = 1200;
    length = sizeof(information);
    assert(!terra_getsockopt(&socket, SOL_TCP, TCP_INFO, (char *)&information, &length));
    assert(information.tcpi_snd_mss == 1200 && information.tcpi_advmss == 1200 &&
           information.tcpi_rcv_mss == UINT16_MAX);
    sk.tcp.rx_opt.user_mss = 0;
    transport.tx_cnt = 32;
    length = sizeof(information);
    assert(!terra_getsockopt(&socket, SOL_TCP, TCP_INFO, (char *)&information, &length));
    assert(information.tcpi_bytes_acked == 1 && information.tcpi_snd_wnd == 49120);
    transport.tx_cnt = transport.peer_fwd_cnt = 0;
    struct msghdr message = {.msg_name = &sk, .msg_namelen = 8};
    send_result = 100;
    assert(check_tcp_send(&socket, &message, 500) == 100 && sk.tcp.bytes_sent == 100 &&
           message.msg_iter == 100);
    length = sizeof(information);
    assert(!terra_getsockopt(&socket, SOL_TCP, TCP_INFO, (char *)&information, &length));
    assert(information.tcpi_bytes_acked == 1 && information.tcpi_snd_wnd == 49052);
    transport.peer_fwd_cnt = 40;
    length = sizeof(information);
    assert(!terra_getsockopt(&socket, SOL_TCP, TCP_INFO, (char *)&information, &length));
    assert(information.tcpi_bytes_acked == 41 && information.tcpi_snd_wnd == 49092);
    transport.peer_buf_alloc = 32;
    length = sizeof(information);
    assert(!terra_getsockopt(&socket, SOL_TCP, TCP_INFO, (char *)&information, &length));
    assert(!information.tcpi_snd_wnd && information.tcpi_bytes_acked == 41 &&
           information.tcpi_snd_mss == UINT16_MAX);
    transport.peer_buf_alloc = UINT32_MAX;
    length = sizeof(information);
    assert(!terra_getsockopt(&socket, SOL_TCP, TCP_INFO, (char *)&information, &length));
    assert(information.tcpi_snd_wnd == TERRA_TCP_SEND_BYTES);

    /* A new carrier reservation precedes its syscall's successful byte bookkeeping. */
    transport.peer_buf_alloc = 49152;
    transport.tx_cnt += 100;
    length = sizeof(information);
    assert(!terra_getsockopt(&socket, SOL_TCP, TCP_INFO, (char *)&information, &length));
    assert(information.tcpi_bytes_acked == 41 && sk.tcp.bytes_sent == 100);
    reserved_before_return = true;
    assert(check_tcp_send(&socket, &message, 100) == 100 && sk.tcp.bytes_sent == 200);
    reserved_before_return = false;
    length = sizeof(information);
    assert(!terra_getsockopt(&socket, SOL_TCP, TCP_INFO, (char *)&information, &length));
    assert(information.tcpi_bytes_acked == 41);
    transport.peer_fwd_cnt = transport.tx_cnt;
    length = sizeof(information);
    assert(!terra_getsockopt(&socket, SOL_TCP, TCP_INFO, (char *)&information, &length));
    assert(information.tcpi_bytes_acked == 201);
    const int failed[] = {-EAGAIN, -EPIPE, 0};
    for (unsigned int i = 0; i < sizeof(failed) / sizeof(failed[0]); i++) {
        send_result = failed[i];
        assert(check_tcp_send(&socket, &message, 100) == failed[i] && sk.tcp.bytes_sent == 200);
    }

    sk.tcp.bytes_sent = (UINT64_C(1) << 32) + 123;
    transport.tx_cnt = 22;
    transport.peer_fwd_cnt = UINT32_MAX - 27;
    length = sizeof(information);
    assert(!terra_getsockopt(&socket, SOL_TCP, TCP_INFO, (char *)&information, &length));
    assert(information.tcpi_bytes_acked == (UINT64_C(1) << 32) + 74);
    transport.peer_fwd_cnt = transport.tx_cnt;
    length = sizeof(information);
    assert(!terra_getsockopt(&socket, SOL_TCP, TCP_INFO, (char *)&information, &length));
    assert(information.tcpi_bytes_acked == sk.tcp.bytes_sent + 1);
    transport.tx_cnt += 100;
    length = sizeof(information);
    assert(!terra_getsockopt(&socket, SOL_TCP, TCP_INFO, (char *)&information, &length));
    assert(information.tcpi_bytes_acked == sk.tcp.bytes_sent + 1);

    state.connected = false;
    length = sizeof(information);
    assert(!terra_getsockopt(&socket, SOL_TCP, TCP_INFO, (char *)&information, &length));
    assert(!information.tcpi_snd_wnd && !information.tcpi_bytes_acked);
    state.connected = true;
    carrier.trans = NULL;
    length = sizeof(information);
    assert(!terra_getsockopt(&socket, SOL_TCP, TCP_INFO, (char *)&information, &length));
    assert(!information.tcpi_snd_wnd && !information.tcpi_bytes_acked);
    carrier.trans = &transport;
    length = -1;
    assert(terra_getsockopt(&socket, SOL_TCP, TCP_INFO, (char *)&information, &length) == -EINVAL);
    length = sizeof(information);
    assert(terra_getsockopt(&socket, SOL_TCP, TCP_INFO, NULL, &length) == -EFAULT);
    state.mode = 0;
    send_result = 7;
    assert(check_tcp_send(&socket, &message, 7) == 7 && native_calls == 1 &&
           sk.tcp.bytes_sent == (UINT64_C(1) << 32) + 123);
    length = sizeof(information);
    assert(terra_getsockopt(&socket, SOL_TCP, TCP_INFO, (char *)&information, &length) == 17 &&
           native_calls == 2);
    socket.type = SOCK_DGRAM;
    state.connected = false;
    const int unsupported_udp_options[][2] = {{SOL_IP, IP_MTU}, {SOL_IPV6, IPV6_MTU}};
    for (unsigned int i = 0; i < sizeof(unsupported_udp_options) / sizeof(unsupported_udp_options[0]); i++) {
        int level = unsupported_udp_options[i][0], option = unsupported_udp_options[i][1];
        state.udp_open = false;
        int before_native_calls = native_calls;
        assert(terra_getsockopt(&socket, level, option, (char *)&information, &length) == 17);
        assert(native_calls == before_native_calls + 1);
        state.udp_open = true;
        before_native_calls = native_calls;
        assert(terra_getsockopt(&socket, level, option, (char *)&information, &length) == -ENOPROTOOPT);
        assert(native_calls == before_native_calls && state.mode == 0);
    }
    const int supported_udp_options[][2] = {{SOL_IP, IP_MTU_DISCOVER},
                                            {SOL_IP, IP_RECVTOS},
                                            {SOL_IPV6, IPV6_DONTFRAG},
                                            {SOL_UDP, UDP_SEGMENT},
                                            {SOL_UDP, UDP_GRO}};
    for (unsigned int i = 0; i < sizeof(supported_udp_options) / sizeof(supported_udp_options[0]); i++) {
        int before_native_calls = native_calls;
        assert(terra_getsockopt(&socket, supported_udp_options[i][0], supported_udp_options[i][1],
                                (char *)&information, &length) == 17);
        assert(native_calls == before_native_calls + 1);
    }
    assert(!sk.locked && !state.select_mutex.locked && !transport.tx_lock);
    return 0;
}
