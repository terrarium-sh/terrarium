#include "socket-stubs.h"
#include "extracted.c"
static struct sockaddr_in6 ipv4_peer(u32 address, u16 port) {
    struct sockaddr_in6 peer = {.sin6_family = AF_INET6, .sin6_port = htons(port)};
    ipv6_addr_set_v4mapped(htonl(address), &peer.sin6_addr);
    return peer;
}
static bool udp_receive_ready(struct terra_tsi_socket *state, struct socket *socket) {
    return terra_udp_receive_ready(state, socket);
}
static int connect_native_after_lock(struct socket *socket, struct sockaddr *peer, int peer_length,
                                     int flags) {
    return terra_connect_locked(socket, peer, peer_length, flags);
}
static int receive_stream_once(struct socket *socket, struct msghdr *message, size_t length, int flags) {
    return terra_recv_stream(terra_socket_state(socket), socket, message, length, flags);
}
static int receive_native_once(struct socket *socket, struct msghdr *message, size_t length, int flags) {
    return terra_recv_native_datagram(terra_socket_state(socket), socket, message, length, flags);
}
static int receive_error_queue(struct socket *socket, struct msghdr *message, size_t length, int flags) {
    return terra_recv_error_queue(terra_socket_state(socket), socket, message, length, flags);
}
static struct sk_buff *queue_datagram(struct sk_buff_head *queue, u8 peer, unsigned int length, u16 segment);
static void resume_external_receive(struct terra_tsi_socket *state, bool datagram) {
    if (datagram) {
        struct sk_buff *skb = queue_datagram(&state->datagrams, 1, 0, 0);
        terra_consume_datagram(state, skb, 0);
    }
}
static int deliver_datagram(struct terra_tsi_socket *state, struct sk_buff *datagram, struct msghdr *message,
                            size_t length, int flags) {
    return terra_deliver_datagram(state, datagram, message, length, flags);
}
static int resume_receive_config(struct socket *socket, int error, int level, int option) {
    if (!error)
        terra_apply_option(terra_socket_state(socket), socket, level, option);
    return error;
}
static int check_udp_send_validation(struct sock *sk, struct msghdr *message, size_t length) {
    u16 segment;
    return terra_udp_send_segment(sk, message, length, &segment);
}

static void peer_checks(void) {
    struct sockaddr_in6 peer = ipv4_peer(0xcb007101, 443), decoded;
    u8 endpoint[TERRA_ENDPOINT_BYTES];
    assert(!terra_encode_peer(endpoint, &peer));
    u8 expected[TERRA_ENDPOINT_BYTES] = {4, 0, 0xbb, 1, 203, 0, 113, 1};
    assert(!memcmp(endpoint, expected, sizeof(expected)));
    assert(!terra_decode_peer(&decoded, endpoint) && !memcmp(&decoded, &peer, sizeof(peer)));
    assert(terra_peer_equal(&peer, &decoded));
    endpoint[8] = 1;
    assert(terra_decode_peer(&decoded, endpoint) == -EPROTO);
    endpoint[8] = 0;
    endpoint[1] = 1;
    assert(terra_decode_peer(&decoded, endpoint) == -EPROTO);
    endpoint[1] = 0;
    endpoint[0] = 5;
    assert(terra_decode_peer(&decoded, endpoint) == -EPROTO);
    struct sockaddr_in6 other = peer;
    other.sin6_port = htons(444);
    assert(!terra_peer_equal(&peer, &other));
    other.sin6_port = 0;
    assert(terra_encode_peer(endpoint, &other) == -EINVAL);
    struct sockaddr_in6 ipv6 = {.sin6_family = AF_INET6, .sin6_port = htons(443)};
    ipv6.sin6_addr.s6_addr[0] = 0xfd;
    ipv6.sin6_addr.s6_addr[15] = 1;
    assert(!terra_encode_peer(endpoint, &ipv6) && endpoint[0] == 6 &&
           !memcmp(endpoint + 4, &ipv6.sin6_addr, 16));
    assert(!terra_decode_peer(&decoded, endpoint) && terra_peer_equal(&decoded, &ipv6) &&
           !terra_peer_equal(&decoded, &peer));
    ipv6.sin6_scope_id = 1;
    assert(terra_encode_peer(endpoint, &ipv6) == -EOPNOTSUPP);
    ipv6.sin6_scope_id = 0;
    ipv6.sin6_flowinfo = 1;
    assert(terra_encode_peer(endpoint, &ipv6) == -EOPNOTSUPP);
}

static void error_checks(void) {
    assert(terra_decode_error(1) == -EACCES && terra_decode_error(10) == -ECONNREFUSED);
    assert(terra_decode_error(11) == -ECONNRESET && terra_decode_error(19) == -ENETDOWN);
    assert(terra_decode_error(20) == -EPROTO && terra_decode_error(21) == -EPROTO &&
           terra_decode_error(0) == -EPROTO);
}

static void opening_checks(void) {
    struct terra_tsi_socket state = {.opened_needed = 32};
    u8 opened[32] = {0x01, 0x01, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0xbb, 1, 203, 0, 113, 1};
    memcpy(state.opened, opened, sizeof(opened));
    assert(!terra_validate_opened(&state));
    unsigned int corrupt[] = {0, 1, 2, 10, 13, 20};
    for (unsigned int i = 0; i < ARRAY_SIZE(corrupt); i++) {
        state.opened[corrupt[i]] ^= 1;
        assert(terra_validate_opened(&state) == -EPROTO);
        state.opened[corrupt[i]] ^= 1;
    }
    put_unaligned_le16(1, state.opened + 8);
    assert(terra_validate_opened(&state) == -EPROTO);
    state.opened_needed = 12;
    assert(terra_validate_opened(&state) == -EACCES);
    put_unaligned_le16(0, state.opened + 8);
    assert(terra_validate_opened(&state) == -EPROTO);
    state.connecting = true;
    state.opening_deadline = 2000;
    jiffies = 1000;
    terra_open_timeout(&state.timeout_work.work);
    assert(state.connecting && !state.connect_error && timeout_delay == 1000 &&
           state.timeout_work.work.queued == 1);
    jiffies = 2000;
    terra_open_timeout(&state.timeout_work.work);
    assert(!state.connecting && state.connect_error == -ETIMEDOUT && shutdowns == 1);
    state.connecting = true;
    state.connect_error = 0;
    state.opening_deadline = 3;
    jiffies = ULONG_MAX - 2;
    terra_open_timeout(&state.timeout_work.work);
    assert(state.connecting && !state.connect_error && timeout_delay == 6);
    state.closing = true;
    jiffies = 3;
    terra_open_timeout(&state.timeout_work.work);
    assert(state.connecting && !state.connect_error);
}
static void clear_datagrams(struct sk_buff_head *queue) {
    while (queue->first) {
        struct sk_buff *next = queue->first->next;
        kfree_skb(queue->first);
        queue->first = next;
    }
    memset(queue, 0, sizeof(*queue));
}

static struct sk_buff *queue_datagram(struct sk_buff_head *queue, u8 peer, unsigned int length, u16 segment) {
    int error;
    struct sk_buff *datagram = alloc_skb_with_frags(0, length, 0, &error, 0);
    for (unsigned int index = 0; index < datagram->shinfo.nr_frags; index++)
        memset(datagram->shinfo.frags[index].page, peer + length, datagram->shinfo.frags[index].size);
    datagram->len = length;
    datagram->data_len = length;
    TERRA_DATAGRAM_CB(datagram)->peer = ipv4_peer(0xcb007100 + peer, 1000 + peer);
    TERRA_DATAGRAM_CB(datagram)->segment = segment;
    skb_queue_tail(queue, datagram);
    return datagram;
}

static int deliver(struct terra_tsi_socket *state, size_t length, int flags, unsigned int *message_flags) {
    struct msghdr message = {0};
    struct sk_buff *datagram = state->datagrams.first;
    received_length = 0;
    gro_cmsgs = 0;
    gro_segment = 0;
    skb_get(datagram);
    int result = deliver_datagram(state, datagram, &message, length, flags);
    kfree_skb(datagram);
    if (message_flags)
        *message_flags = message.msg_flags;
    return result;
}

/* Reads take whole segments under GRO, single datagrams otherwise, and merge only same-peer,
 * same-size runs ending in at most one shorter, non-empty datagram. */
static void udp_gro_checks(void) {
    struct sock sk = {.udp.gro_enabled = true};
    struct terra_tsi_socket state = {.sk = &sk};
    unsigned int flags;
    for (int i = 0; i < 3; i++)
        queue_datagram(&state.datagrams, 1, 1200, 0);
    queue_datagram(&state.datagrams, 1, 500, 0);
    queue_datagram(&state.datagrams, 1, 1200, 0);
    assert(deliver(&state, 65536, 0, NULL) == 4100 && gro_cmsgs == 1 && gro_segment == 1200 &&
           state.datagrams.qlen == 1);
    assert(received[0] == (u8)1201 && received[3599] == (u8)1201 && received[3600] == (u8)(1 + 500));
    assert(deliver(&state, 65536, 0, NULL) == 1200 && !gro_cmsgs && !state.datagrams.qlen);
    queue_datagram(&state.datagrams, 2, 2500, 1000);
    sk.udp.gro_enabled = false;
    for (int i = 0; i < 2; i++)
        assert(deliver(&state, 65536, 0, NULL) == 1000 && !gro_cmsgs && state.datagrams.qlen == 1);
    assert(deliver(&state, 65536, 0, NULL) == 500 && !gro_cmsgs && !state.datagrams.qlen);
    sk.udp.gro_enabled = true;
    queue_datagram(&state.datagrams, 2, 2500, 1000);
    assert(deliver(&state, 2400, 0, NULL) == 2000 && gro_cmsgs == 1 && gro_segment == 1000 &&
           state.datagrams.qlen == 1);
    assert(deliver(&state, 2400, 0, NULL) == 500 && !gro_cmsgs && !state.datagrams.qlen);
    queue_datagram(&state.datagrams, 3, 3000, 1000);
    queue_datagram(&state.datagrams, 3, 1000, 0);
    queue_datagram(&state.datagrams, 3, 2000, 1000);
    queue_datagram(&state.datagrams, 3, 2400, 1200);
    assert(deliver(&state, 65536, 0, NULL) == 6000 && gro_segment == 1000 && state.datagrams.qlen == 1);
    assert(deliver(&state, 65536, MSG_PEEK, NULL) == 1200 && !gro_cmsgs && state.datagrams.qlen == 1);
    assert(deliver(&state, 65536, 0, NULL) == 2400 && gro_segment == 1200 && !state.datagrams.qlen);
    queue_datagram(&state.datagrams, 4, 1000, 0);
    queue_datagram(&state.datagrams, 5, 1000, 0);
    assert(deliver(&state, 65536, 0, NULL) == 1000 && !gro_cmsgs && state.datagrams.qlen == 1);
    clear_datagrams(&state.datagrams);
    queue_datagram(&state.datagrams, 6, 1200, 0);
    assert(deliver(&state, 1000, 0, &flags) == 1000 && (flags & MSG_TRUNC) && !state.datagrams.qlen);
    queue_datagram(&state.datagrams, 6, 1200, 0);
    assert(deliver(&state, 1000, MSG_TRUNC, NULL) == 1200 && !state.datagrams.qlen);
    for (int i = 0; i < TERRA_UDP_MAX_SEGMENTS + 2; i++)
        queue_datagram(&state.datagrams, 7, 10, 0);
    assert(deliver(&state, 65536, 0, NULL) == 10 * TERRA_UDP_MAX_SEGMENTS && gro_segment == 10 &&
           state.datagrams.qlen == 2);
    clear_datagrams(&state.datagrams);
    for (int i = 0; i < 4; i++)
        queue_datagram(&state.datagrams, 8, 1000, 0);
    assert(deliver(&state, 1999, 0, NULL) == 1000 && state.datagrams.qlen == 3);
    clear_datagrams(&state.datagrams);
    queue_datagram(&state.datagrams, 9, 0, 0);
    queue_datagram(&state.datagrams, 9, 7, 0);
    assert(deliver(&state, 65536, 0, NULL) == 0 && state.datagrams.qlen == 1);
    clear_datagrams(&state.datagrams);
    for (int i = 0; i < 3; i++)
        queue_datagram(&state.datagrams, 10, 4000, 0);
    iter_receive_limit = 4000;
    assert(deliver(&state, 65536, 0, NULL) == -EFAULT && state.datagrams.qlen == 1);
    clear_datagrams(&state.datagrams);
    iter_receive_limit = SIZE_MAX;
}

static void check_udp_resume(struct terra_tsi_socket *state, bool needed) {
    struct socket outer = {.sk = state->sk, .type = SOCK_DGRAM};
    struct msghdr message = {0};
    state->sk->sk_user_data = state;
    state->udp_work.queued = 0;
    terra_resume_udp(state);
    assert(state->udp_work.queued == (needed ? 1 : 0));
    state->udp_work.queued = 0;
    resume_external_receive(state, true);
    assert(state->udp_work.queued == (needed ? 1 : 0));
    state->udp_work.queued = 0;
    resume_external_receive(state, false);
    assert(!state->udp_work.queued);
    const int results[] = {0, 1, -EFAULT, -EAGAIN};
    for (unsigned int i = 0; i < ARRAY_SIZE(results); i++) {
        native_result = results[i];
        const int flags[] = {0, MSG_PEEK, MSG_DONTWAIT, MSG_PEEK | MSG_DONTWAIT};
        for (unsigned int f = 0; f < ARRAY_SIZE(flags); f++) {
            native_receive_calls = 0;
            state->udp_work.queued = 0;
            assert(receive_native_once(&outer, &message, 0, flags[f]) == native_result);
            assert(native_receive_calls == 1 && native_receive_flags == (flags[f] | MSG_DONTWAIT));
            assert(state->udp_work.queued == (needed ? 1 : 0));
            native_receive_calls = 0;
            state->udp_work.queued = 0;
            assert(receive_error_queue(&outer, &message, 0, flags[f] | MSG_ERRQUEUE) == native_result);
            assert(native_receive_calls == 1 && native_receive_flags == (flags[f] | MSG_ERRQUEUE));
            assert(state->udp_work.queued == (needed ? 1 : 0));
        }
    }
    const int options[][2] = {{SOL_SOCKET, SO_RCVBUF}, {SOL_IP, IP_RECVERR}, {SOL_IPV6, IPV6_RECVERR}};
    for (unsigned int i = 0; i < ARRAY_SIZE(options); i++) {
        state->udp_work.queued = 0;
        assert(!resume_receive_config(&outer, 0, options[i][0], options[i][1]));
        assert(state->udp_work.queued == (needed ? 1 : 0));
        state->udp_work.queued = 0;
        assert(resume_receive_config(&outer, -EFAULT, options[i][0], options[i][1]) == -EFAULT);
        assert(!state->udp_work.queued);
    }
    state->udp_work.queued = 0;
    assert(!resume_receive_config(&outer, 0, SOL_SOCKET, SO_SNDBUF));
    assert(!resume_receive_config(&outer, 0, SOL_IP, IP_TTL));
    assert(!state->udp_work.queued);
}
static void udp_resume_checks(void) {
    struct vsock_sock transport = {.sk.sk_state = TCP_ESTABLISHED};
    struct sock outer = {0};
    struct socket socket = {.sk = &transport.sk};
    struct proto_ops native = {.poll = carrier_poll, .recvmsg = native_receive};
    struct terra_tsi_socket state = {
        .stream = &socket, .sk = &outer, .udp_open = true, .native_ops = &native};
    carrier_poll_mask = EPOLLIN;
    for (carrier_available = 0; carrier_available < TERRA_HEADER_BYTES; carrier_available++)
        check_udp_resume(&state, false);
    carrier_available = TERRA_HEADER_BYTES;
    check_udp_resume(&state, true);
    carrier_available = 0;
    transport.sk.sk_err = EIO;
    check_udp_resume(&state, true);
    transport.sk.sk_err = 0;
    transport.sk.sk_state = TCP_CLOSE;
    check_udp_resume(&state, true);
    transport.sk.sk_state = TCP_ESTABLISHED;
    transport.sk.sk_shutdown = RCV_SHUTDOWN;
    check_udp_resume(&state, true);
    transport.sk.sk_shutdown = 0;
    transport.peer_shutdown = SEND_SHUTDOWN;
    for (carrier_available = 0; carrier_available < TERRA_HEADER_BYTES; carrier_available++)
        check_udp_resume(&state, true);
    transport.peer_shutdown = 0;
    carrier_available = 0;
    check_udp_resume(&state, false);
    state.udp_open = false;
    state.stream = NULL;
    carrier_available = TERRA_HEADER_BYTES;
    state.udp_work.queued = 0;
    terra_resume_udp(&state);
    resume_external_receive(&state, true);
    assert(!state.udp_work.queued);
    struct socket native_socket = {.sk = &outer, .type = SOCK_DGRAM};
    struct msghdr message = {0};
    native_result = -EFAULT;
    native_receive_calls = 0;
    assert(receive_error_queue(&native_socket, &message, 0, MSG_ERRQUEUE | MSG_DONTWAIT) == -EFAULT);
    assert(native_receive_calls == 1 && native_receive_flags == (MSG_ERRQUEUE | MSG_DONTWAIT));
    assert(!state.udp_work.queued);
    assert(!resume_receive_config(&native_socket, 0, SOL_SOCKET, SO_RCVBUF));
    assert(!state.udp_work.queued);
}

static size_t datagram_frame(u8 *frame, const struct sockaddr_in6 *peer, size_t length, u16 segment,
                             u16 reserved) {
    terra_frame_header(frame, TERRA_OP_UDP_DATAGRAM,
                       TERRA_ENDPOINT_BYTES + TERRA_UDP_SEGMENT_FIELD_BYTES + length);
    assert(!terra_encode_peer(frame + TERRA_HEADER_BYTES, peer));
    put_unaligned_le16(segment, frame + TERRA_HEADER_BYTES + TERRA_ENDPOINT_BYTES);
    put_unaligned_le16(reserved, frame + TERRA_HEADER_BYTES + TERRA_ENDPOINT_BYTES + 2);
    for (size_t index = 0; index < length; index++)
        frame[TERRA_HEADER_BYTES + TERRA_ENDPOINT_BYTES + TERRA_UDP_SEGMENT_FIELD_BYTES + index] =
            index % 251;
    return TERRA_HEADER_BYTES + TERRA_ENDPOINT_BYTES + TERRA_UDP_SEGMENT_FIELD_BYTES + length;
}

/* Datagram frames queue as one skb carrying their segment size (0 for one datagram); malformed ones retire
 * the socket, unallocatable ones are skipped, and a full queue or retained error memory at the receive buffer
 * leaves the frame on the carrier, while an empty queue waives only the byte cap. */
static void udp_segmented_receive_checks(struct terra_tsi_socket *state,
                                         const struct sockaddr_in6 *peer) {
    size_t length = datagram_frame(carrier, peer, TERRA_UDP_RUN_BYTES, 1024, 0);
    carrier_available = length;
    assert(length == TERRA_UDP_CARRIER_BYTES && terra_receive_udp_frame(state) &&
           state->datagrams.qlen == 1 && !carrier_available);
    struct sk_buff *queued = state->datagrams.first;
    assert(terra_datagram_bytes(queued) == TERRA_UDP_RUN_BYTES && terra_datagram_segment(queued) == 1024);
    assert(skb_byte(queued, 5000) == 5000 % 251 &&
           skb_byte(queued, queued->len - 1) == (TERRA_UDP_RUN_BYTES - 1) % 251);
    length = datagram_frame(carrier, peer, 2500, 1000, 0);
    carrier_available = length;
    state->sk->sk_rcvbuf = 1000;
    assert(!terra_receive_udp_frame(state) && !state->udp_failed && carrier_available == (s64)length &&
           state->datagrams.qlen == 1);
    clear_datagrams(&state->datagrams);
    state->sk->sk_rmem_alloc = 1000;
    assert(!terra_receive_udp_frame(state) && !state->udp_failed && carrier_available == (s64)length &&
           !state->datagrams.qlen);
    state->sk->sk_rmem_alloc = 999;
    assert(terra_receive_udp_frame(state) && state->datagrams.qlen == 1 &&
           terra_datagram_segment(state->datagrams.first) == 1000);
    clear_datagrams(&state->datagrams);
    state->sk->sk_rcvbuf = 1 << 20;
    state->sk->sk_rmem_alloc = 0;
    skb_allocation_fails = true;
    length = datagram_frame(carrier, peer, 2500, 1000, 0);
    datagram_frame(carrier + length, peer, 2500, 1000, 0);
    carrier_available = 2 * length;
    assert(terra_receive_udp_frame(state) && !state->datagrams.qlen && carrier_available == (s64)length);
    skb_allocation_fails = false;
    assert(terra_receive_udp_frame(state) && state->datagrams.qlen == 1);
    clear_datagrams(&state->datagrams);
    carrier_available = datagram_frame(carrier, peer, TERRA_UDP_DATAGRAM, 0, 0);
    assert(terra_receive_udp_frame(state) && state->datagrams.qlen == 1 &&
           !TERRA_DATAGRAM_CB(state->datagrams.first)->segment);
    assert(terra_datagram_segment(state->datagrams.first) == TERRA_UDP_DATAGRAM);
    clear_datagrams(&state->datagrams);
    const struct {
        size_t length;
        u16 segment, reserved;
    } malformed[] = {{TERRA_UDP_DATAGRAM + 1, 0, 0},
                     {2500, TERRA_UDP_DATAGRAM + 1, 0},
                     {1000, 1000, 0},
                     {999, 1000, 0},
                     {65, 1, 0},
                     {2500, 1000, 1},
                     {7, 0, 1}};
    for (unsigned int i = 0; i < ARRAY_SIZE(malformed); i++) {
        carrier_available =
            datagram_frame(carrier, peer, malformed[i].length, malformed[i].segment, malformed[i].reserved);
        assert(!terra_receive_udp_frame(state) && state->udp_failed == -EPROTO && !state->datagrams.qlen);
        state->udp_failed = 0;
        state->sk->sk_err = 0;
    }
    datagram_frame(carrier, peer, 1, 1, 0);
    carrier_available = TERRA_HEADER_BYTES;
    put_unaligned_le32(TERRA_ENDPOINT_BYTES + TERRA_UDP_SEGMENT_FIELD_BYTES + TERRA_UDP_RUN_BYTES + 1,
                       carrier + 4);
    assert(!terra_receive_udp_frame(state) && state->udp_failed == -EPROTO);
    state->udp_failed = 0;
    state->sk->sk_err = 0;
}

static void udp_checks(void) {
    struct virtio_vsock_sock capacity = {.buf_alloc = 24576, .peer_buf_alloc = 24576};
    struct vsock_sock transport = {.sk.sk_state = TCP_ESTABLISHED, .trans = &capacity};
    struct sock outer = {.sk_data_ready = decoded_data_ready, .sk_rcvbuf = 1 << 20};
    struct socket socket = {.sk = &transport.sk};
    u8 outgoing[4124];
    struct terra_tsi_socket state = {.sk = &outer, .stream = &socket, .udp_frame = outgoing, .wait = 123};
    struct sockaddr_in6 peer = ipv4_peer(0xcb007101, 80);
    u8 frame[33] = {0};
    terra_frame_header(frame, TERRA_OP_UDP_DATAGRAM, 25);
    assert(!terra_encode_peer(frame + 8, &peer));
    frame[32] = 'D';
    memcpy(carrier, frame, 33);
    carrier_available = 10;
    assert(!terra_receive_udp_frame(&state) && !state.udp_failed && carrier_available == 10);
    int before_delivery_wakes = wakes;
    int before_data_wakes = decoded_data_wakes;
    carrier_available = 33;
    assert(terra_receive_udp_frame(&state) && state.datagrams.qlen == 1);
    assert(decoded_data_wakes == before_data_wakes + 1 && wakes == before_delivery_wakes);
    assert(state.datagrams.first->len == 1 && skb_byte(state.datagrams.first, 0) == 'D');
    assert(terra_datagram_bytes(state.datagrams.first) == 1 &&
           !TERRA_DATAGRAM_CB(state.datagrams.first)->segment);
    clear_datagrams(&state.datagrams);
    memcpy(carrier, frame, 33);
    memcpy(carrier + 33, frame, 33);
    carrier_available = 66;
    assert(terra_receive_udp_frame(&state) && terra_receive_udp_frame(&state) && state.datagrams.qlen == 2);
    assert(decoded_data_wakes == before_data_wakes + 3 && wakes == before_delivery_wakes);
    assert(!terra_receive_udp_frame(&state) && !state.udp_failed);
    clear_datagrams(&state.datagrams);
    outer.sk_shutdown = RCV_SHUTDOWN;
    memcpy(carrier, frame, 33);
    carrier_available = 33;
    assert(terra_receive_udp_frame(&state) && !state.datagrams.qlen);
    assert(decoded_data_wakes == before_data_wakes + 3 && wakes == before_delivery_wakes);
    outer.sk_shutdown = 0;
    for (unsigned int available = 0; available < 33; available++) {
        memcpy(carrier, frame, 33);
        carrier_available = available;
        transport.peer_shutdown = SEND_SHUTDOWN;
        assert(!terra_receive_udp_frame(&state));
        assert(state.udp_failed == (available ? -EPROTO : -ENETDOWN));
        state.udp_failed = 0;
        outer.sk_err = 0;
    }
    transport.peer_shutdown = 0;
    terra_frame_header(frame, TERRA_OP_UDP_ERROR, 24);
    put_unaligned_le16(1, frame + 8);
    put_unaligned_le16(0, frame + 10);
    assert(!terra_encode_peer(frame + 12, &peer));
    memcpy(carrier, frame, 32);
    carrier_available = 32;
    int before_queued_error_wakes = wakes;
    assert(terra_receive_udp_frame(&state) && outer.sk_err == EACCES && queued_errors == 1);
    assert(wakes == before_queued_error_wakes + 1);
    struct msghdr message = {.msg_iter.bytes = (const u8 *)"abc"};
    carrier_space = 0;
    assert(terra_send_udp(&state, &peer, &message, 3, 0, true) == -EACCES &&
           !outer.sk_err && !sends);
    assert(terra_send_udp(&state, &peer, &message, 3, 0, true) == -EAGAIN && !sends);
    for (wait_action = 1; wait_action <= 2; wait_action++) {
        outer.sk_shutdown = 0;
        message.msg_iter.bytes = (const u8 *)"abc";
        waiting_socket = &outer;
        int expected = wait_action == 1 ? -EPIPE : -EACCES;
        assert(terra_send_udp(&state, &peer, &message, 3, 0, false) == expected && !sends);
    }
    assert(waits == 2 && !outer.sk_err);
    outer.sk_shutdown = 0;
    wait_action = 0;
    message.msg_iter.bytes = (const u8 *)"abc";
    assert(terra_send_udp(&state, &peer, &message, 3, 0, false) == 3 && sends == 1 &&
           waits == 3);
    assert(get_unaligned_le16(carrier) == TERRA_OP_UDP_SEND && get_unaligned_le32(carrier + 4) == 27 &&
           !memcmp(carrier + 32, "abc", 3));
    assert(!get_unaligned_le32(carrier + 28));
    terra_frame_header(frame, TERRA_OP_UDP_ERROR, 24);
    put_unaligned_le16(21, frame + 8);
    memcpy(carrier, frame, 32);
    carrier_available = 32;
    int before_error_wakes = wakes;
    assert(!terra_receive_udp_frame(&state) && state.udp_failed == -EPROTO);
    state.udp_failed = 0;
    assert(wakes == before_error_wakes + 1);
    udp_segmented_receive_checks(&state, &peer);
}
static void udp_control_checks(void) {
    struct sock sk = {.sk_family = AF_INET, .udp.gso_size = 1200};
    u16 segment;
    union {
        struct cmsghdr alignment;
        u8 bytes[128];
    } control = {0};
    struct msghdr message = {0};
    assert(!terra_udp_control(&sk, &message, &segment) && segment == 1200);
    assert(!check_udp_send_validation(&sk, &message, 64 * 1200));
    assert(check_udp_send_validation(&sk, &message, 64 * 1200 + 1) == -EINVAL);
    sk.udp.gso_size = 0;
    assert(!check_udp_send_validation(&sk, &message, TERRA_UDP_DATAGRAM));
    assert(check_udp_send_validation(&sk, &message, TERRA_UDP_DATAGRAM + 1) == -EMSGSIZE);
    sk.udp.gso_size = TERRA_UDP_DATAGRAM + 1;
    assert(check_udp_send_validation(&sk, &message, 1) == -EINVAL);
    sk.udp.gso_size = 1200;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(struct cmsghdr) - 1;
    assert(terra_udp_control(&sk, &message, &segment) == -EINVAL);
    struct cmsghdr *entry = (void *)control.bytes;
    entry->cmsg_level = SOL_UDP;
    entry->cmsg_type = UDP_SEGMENT;
    entry->cmsg_len = CMSG_LEN(sizeof(u16));
    message.msg_controllen = CMSG_SPACE(sizeof(u16));
    const u16 invalid_segments[] = {0, TERRA_UDP_DATAGRAM + 1};
    for (unsigned int i = 0; i < ARRAY_SIZE(invalid_segments); i++) {
        memcpy(CMSG_DATA(entry), &invalid_segments[i], sizeof(u16));
        assert(terra_udp_control(&sk, &message, &segment) == -EINVAL);
    }
    u16 override = 1000;
    memcpy(CMSG_DATA(entry), &override, sizeof(override));
    assert(!terra_udp_control(&sk, &message, &segment) && segment == override);
    assert(!check_udp_send_validation(&sk, &message, 64 * 1000));
    assert(check_udp_send_validation(&sk, &message, 64 * 1000 + 1) == -EINVAL);
    entry->cmsg_len = CMSG_LEN(sizeof(u16) + 1);
    assert(terra_udp_control(&sk, &message, &segment) == -EINVAL);
    entry->cmsg_len = sizeof(control.bytes) + 1;
    assert(terra_udp_control(&sk, &message, &segment) == -EINVAL);
    entry->cmsg_level = SOL_IP;
    entry->cmsg_type = IP_TOS;
    int ecn = 2;
    memcpy(CMSG_DATA(entry), &ecn, sizeof(ecn));
    entry->cmsg_len = CMSG_LEN(sizeof(u8));
    message.msg_controllen = CMSG_SPACE(sizeof(u8));
    assert(!terra_udp_control(&sk, &message, &segment) && segment == 1200);
    entry->cmsg_len = CMSG_LEN(sizeof(ecn));
    message.msg_controllen = CMSG_SPACE(sizeof(ecn));
    assert(!terra_udp_control(&sk, &message, &segment));
    const int invalid_tos[] = {-1, 256};
    for (unsigned int i = 0; i < ARRAY_SIZE(invalid_tos); i++) {
        memcpy(CMSG_DATA(entry), &invalid_tos[i], sizeof(int));
        assert(terra_udp_control(&sk, &message, &segment) == -EINVAL);
    }
    entry->cmsg_len = CMSG_LEN(0);
    assert(terra_udp_control(&sk, &message, &segment) == -EINVAL);
    entry->cmsg_level = SOL_IPV6;
    entry->cmsg_type = IPV6_TCLASS;
    entry->cmsg_len = CMSG_LEN(sizeof(int));
    ecn = -1;
    memcpy(CMSG_DATA(entry), &ecn, sizeof(ecn));
    assert(!terra_udp_control(&sk, &message, &segment));
    ecn = 256;
    memcpy(CMSG_DATA(entry), &ecn, sizeof(ecn));
    assert(terra_udp_control(&sk, &message, &segment) == -EINVAL);
    entry->cmsg_level = 0x7fff;
    assert(terra_udp_control(&sk, &message, &segment) == -EOPNOTSUPP);
    entry->cmsg_level = SOL_IP;
    entry->cmsg_type = IP_PKTINFO;
    entry->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
    message.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));
    struct in_pktinfo packet = {0};
    memcpy(CMSG_DATA(entry), &packet, sizeof(packet));
    assert(!terra_udp_control(&sk, &message, &segment));
    packet.ipi_ifindex = 1;
    memcpy(CMSG_DATA(entry), &packet, sizeof(packet));
    assert(terra_udp_control(&sk, &message, &segment) == -EOPNOTSUPP);
    packet.ipi_ifindex = 0;
    sk.inet.inet_rcv_saddr = htonl(0xc0000201);
    packet.ipi_spec_dst.s_addr = sk.inet.inet_rcv_saddr;
    memcpy(CMSG_DATA(entry), &packet, sizeof(packet));
    assert(!terra_udp_control(&sk, &message, &segment));
    packet.ipi_spec_dst.s_addr = htonl(0xc0000202);
    memcpy(CMSG_DATA(entry), &packet, sizeof(packet));
    assert(terra_udp_control(&sk, &message, &segment) == -EINVAL);
    entry->cmsg_level = SOL_IPV6;
    entry->cmsg_type = IPV6_PKTINFO;
    entry->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
    message.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));
    struct in6_pktinfo packet6 = {0};
    memcpy(CMSG_DATA(entry), &packet6, sizeof(packet6));
    assert(terra_udp_control(&sk, &message, &segment) == -EINVAL);
    sk.sk_family = AF_INET6;
    assert(!terra_udp_control(&sk, &message, &segment));
    packet6.ipi6_ifindex = 1;
    memcpy(CMSG_DATA(entry), &packet6, sizeof(packet6));
    assert(terra_udp_control(&sk, &message, &segment) == -EOPNOTSUPP);
    packet6.ipi6_ifindex = 0;
    sk.sk_v6_rcv_saddr.s6_addr[15] = 1;
    packet6.ipi6_addr = sk.sk_v6_rcv_saddr;
    memcpy(CMSG_DATA(entry), &packet6, sizeof(packet6));
    assert(!terra_udp_control(&sk, &message, &segment));
    packet6.ipi6_addr.s6_addr[15] = 2;
    memcpy(CMSG_DATA(entry), &packet6, sizeof(packet6));
    assert(terra_udp_control(&sk, &message, &segment) == -EINVAL);
    memset(control.bytes, 0, sizeof(control.bytes));
    entry->cmsg_level = SOL_IP;
    entry->cmsg_type = IP_TOS;
    entry->cmsg_len = CMSG_LEN(sizeof(u8));
    *CMSG_DATA(entry) = 2;
    struct cmsghdr *second = (void *)(control.bytes + CMSG_SPACE(sizeof(u8)));
    second->cmsg_level = SOL_UDP;
    second->cmsg_type = UDP_SEGMENT;
    second->cmsg_len = CMSG_LEN(sizeof(u16));
    memcpy(CMSG_DATA(second), &override, sizeof(override));
    message.msg_controllen = CMSG_SPACE(sizeof(u8)) + CMSG_SPACE(sizeof(u16));
    assert(!terra_udp_control(&sk, &message, &segment) && segment == override);
    second->cmsg_level = 0x7fff;
    assert(terra_udp_control(&sk, &message, &segment) == -EOPNOTSUPP);
}
static void udp_receive_shutdown_checks(void) {
    struct sock sk = {0};
    struct proto_ops native = {.poll = carrier_poll};
    struct socket socket = {.sk = &sk};
    struct terra_tsi_socket state = {.sk = &sk, .native_ops = &native};
    carrier_poll_mask = 0;
    assert(!udp_receive_ready(&state, &socket));
    sk.sk_shutdown = SEND_SHUTDOWN;
    assert(!udp_receive_ready(&state, &socket));
    sk.sk_shutdown = RCV_SHUTDOWN;
    assert(udp_receive_ready(&state, &socket));
}
static int native_listen_result, native_listens, native_connects;
static struct terra_tsi_socket *selecting_state;
static int native_listen(struct socket *socket, int backlog) {
    struct terra_tsi_socket *state = terra_socket_state(socket);
    assert(state->select_mutex.locked && backlog == 7);
    native_listens++;
    return native_listen_result;
}
static int native_connect(struct socket *socket, struct sockaddr *peer, int length, int flags) {
    (void)peer;
    (void)length;
    (void)flags;
    assert(terra_socket_state(socket)->select_mutex.locked);
    native_connects++;
    return -EISCONN;
}
static void finish_listen_before_connect_lock(void) {
    selecting_state->mode = TERRA_SOCKET_NATIVE;
}
static void listen_selection_checks(void) {
    struct sock sk = {0};
    struct proto_ops native = {.listen = native_listen, .connect = native_connect};
    struct socket socket = {.sk = &sk, .type = SOCK_STREAM};
    struct sockaddr peer = {.sa_family = AF_INET};
    struct terra_tsi_socket state = {.sk = &sk, .native_ops = &native};
    sk.sk_user_data = &state;
    native_listen_result = -EADDRINUSE;
    assert(terra_listen(&socket, 7) == -EADDRINUSE && !state.mode && !state.select_mutex.locked &&
           native_listens == 1);
    native_listen_result = 0;
    assert(!terra_listen(&socket, 7) && state.mode == TERRA_SOCKET_NATIVE && !state.select_mutex.locked &&
           native_listens == 2);
    state.mode = TERRA_SOCKET_EXTERNAL;
    assert(terra_listen(&socket, 7) == -EOPNOTSUPP && state.mode == TERRA_SOCKET_EXTERNAL &&
           !state.select_mutex.locked && native_listens == 2);
    state.mode = 0;
    select_lock_error = -EINTR;
    assert(terra_listen(&socket, 7) == -EINTR && !state.mode && !state.select_mutex.locked &&
           native_listens == 2);
    select_lock_error = 0;
    selecting_state = &state;
    select_lock_hook = finish_listen_before_connect_lock;
    assert(connect_native_after_lock(&socket, &peer, sizeof(peer), 0) == -EISCONN);
    assert(native_connects == 1 && state.mode == TERRA_SOCKET_NATIVE && !state.select_mutex.locked);
}

static size_t udp_frame_length(size_t length) {
    return TERRA_HEADER_BYTES + TERRA_ENDPOINT_BYTES + TERRA_UDP_SEGMENT_FIELD_BYTES + length;
}

/* Every send is one UDP_SEND frame; its segment field is set only when a GSO payload spans several datagrams.
 */
static void check_udp_frames(const struct sockaddr_in6 *peer, const u8 *payload, size_t length,
                             u16 segment) {
    u8 endpoint[TERRA_ENDPOINT_BYTES];
    assert(!terra_encode_peer(endpoint, peer));
    size_t prefix = udp_frame_length(0);
    assert(get_unaligned_le16(carrier) == TERRA_OP_UDP_SEND);
    assert(!get_unaligned_le16(carrier + 2));
    assert(get_unaligned_le32(carrier + 4) == udp_frame_length(length) - TERRA_HEADER_BYTES);
    assert(!memcmp(carrier + TERRA_HEADER_BYTES, endpoint, sizeof(endpoint)));
    assert(get_unaligned_le16(carrier + TERRA_HEADER_BYTES + TERRA_ENDPOINT_BYTES) ==
           (segment && length > segment ? segment : 0));
    assert(!get_unaligned_le16(carrier + TERRA_HEADER_BYTES + TERRA_ENDPOINT_BYTES + 2));
    assert(!memcmp(carrier + prefix, payload, length));
}

static void udp_gso_checks(void) {
    struct virtio_vsock_sock capacity = {.buf_alloc = 24576, .peer_buf_alloc = 24576};
    struct vsock_sock transport = {.sk.sk_state = TCP_ESTABLISHED, .trans = &capacity};
    struct sock outer = {0};
    struct socket socket = {.sk = &transport.sk};
    u8 outgoing[TERRA_UDP_FRAME_BYTES];
    struct terra_tsi_socket state = {.sk = &outer, .stream = &socket, .udp_frame = outgoing, .wait = 123};
    struct sockaddr_in6 peer = ipv4_peer(0xcb007101, 80);
    u8 payload[8193];
    for (unsigned int i = 0; i < sizeof(payload); i++)
        payload[i] = i % 251;
    const size_t exact_buffer_payload = TERRA_UDP_FRAME_BYTES - udp_frame_length(0);
    const struct {
        size_t length;
        u16 segment;
    } cases[] = {{0, 0},
                 {0, 1200},
                 {7, 1200},
                 {1200, 1200},
                 {4096, 0},
                 {3600, 1200},
                 {6000, 1200},
                 {2401, 1000},
                 {8193, 4096},
                 {64, 1},
                 {exact_buffer_payload, TERRA_UDP_DATAGRAM / 2},
                 {exact_buffer_payload + 1, TERRA_UDP_DATAGRAM / 2}};
    for (unsigned int i = 0; i < ARRAY_SIZE(cases); i++) {
        struct msghdr message = {.msg_iter.bytes = payload};
        carrier_space = 10000;
        int before_sends = sends, before_allocations = allocations;
        assert(terra_send_udp(&state, &peer, &message, cases[i].length, cases[i].segment,
                              true) == (int)cases[i].length);
        assert(sends == before_sends + 1 && message.msg_iter.bytes == payload + cases[i].length);
        assert(allocations ==
               before_allocations + (udp_frame_length(cases[i].length) > TERRA_UDP_FRAME_BYTES));
        assert(!live_allocations && !capacity.tx_lock);
        check_udp_frames(&peer, payload, cases[i].length, cases[i].segment);
    }
    size_t framed = udp_frame_length(2401);
    struct msghdr message = {.msg_iter.bytes = payload};
    int before_sends = sends, before_allocations = allocations;
    carrier[0] = 0xa5;
    carrier_space = framed - 1;
    int before_requests = credit_requests;
    assert(terra_send_udp(&state, &peer, &message, 2401, 1000, true) == -EAGAIN);
    assert(sends == before_sends && allocations == before_allocations && message.msg_iter.bytes == payload &&
           carrier[0] == 0xa5);
    assert(credit_requests == before_requests + 1 && !transport.sk.locked);
    capacity.buf_alloc = framed - 1;
    capacity.peer_buf_alloc = framed;
    carrier_space = 10000;
    assert(terra_send_udp(&state, &peer, &message, 2401, 1000, true) == -EMSGSIZE);
    capacity.buf_alloc = framed;
    capacity.peer_buf_alloc = framed - 1;
    assert(terra_send_udp(&state, &peer, &message, 2401, 1000, false) == -EMSGSIZE);
    assert(sends == before_sends && allocations == before_allocations && message.msg_iter.bytes == payload &&
           carrier[0] == 0xa5);
    assert(credit_requests == before_requests + 1);
    capacity.peer_buf_alloc = framed;
    carrier_space = framed;
    assert(terra_send_udp(&state, &peer, &message, 2401, 1000, true) == 2401 &&
           sends == before_sends + 1);
    check_udp_frames(&peer, payload, 2401, 1000);
    capacity.buf_alloc = capacity.peer_buf_alloc = 24576;
    carrier_space = framed - 1;
    message.msg_iter.bytes = payload;
    int before_waits = waits;
    waiting_socket = &outer;
    wait_action = 0;
    assert(terra_send_udp(&state, &peer, &message, 2401, 1000, false) == 2401);
    assert(waits == before_waits + 1 && sends == before_sends + 2);
    check_udp_frames(&peer, payload, 2401, 1000);
    assert(credit_requests == before_requests + 2 && !transport.sk.locked);
    message.msg_iter.bytes = payload;
    before_sends = sends;
    before_allocations = allocations;
    carrier[0] = 0xa5;
    allocation_fails = true;
    assert(terra_send_udp(&state, &peer, &message, 6000, 1200, true) == -ENOMEM);
    assert(sends == before_sends && allocations == before_allocations + 1 &&
           message.msg_iter.bytes == payload && !live_allocations && carrier[0] == 0xa5);
    allocation_fails = false;
    before_allocations = allocations;
    iter_copy_limit = 1000;
    assert(terra_send_udp(&state, &peer, &message, 2401, 1000, true) == -EFAULT);
    assert(sends == before_sends && allocations == before_allocations && message.msg_iter.bytes == payload &&
           !live_allocations && carrier[0] == 0xa5);
    message.msg_iter.bytes = payload;
    iter_copy_limit = 1200;
    assert(terra_send_udp(&state, &peer, &message, 6000, 1200, true) == -EFAULT);
    assert(sends == before_sends && allocations == before_allocations + 1 &&
           message.msg_iter.bytes == payload && !live_allocations && carrier[0] == 0xa5);
    iter_copy_limit = SIZE_MAX;
    transport.trans = NULL;
    assert(terra_send_udp(&state, &peer, &message, 2401, 1000, true) == -ENETDOWN &&
           sends == before_sends);
}

static void udp_atomic_credit_checks(void) {
    const unsigned int peer_capacity = 48 * 1024, framed = udp_frame_length(40 * 1200);
    struct virtio_vsock_sock capacity = {.buf_alloc = 64 * 1024, .peer_buf_alloc = peer_capacity};
    struct vsock_sock transport = {.sk.sk_state = TCP_ESTABLISHED, .trans = &capacity};
    struct sock outer = {0};
    struct socket socket = {.sk = &transport.sk};
    u8 outgoing[TERRA_UDP_FRAME_BYTES];
    struct terra_tsi_socket state = {.sk = &outer, .stream = &socket, .udp_frame = outgoing, .wait = 123};
    struct sockaddr_in6 peer = ipv4_peer(0xcb007101, 80);
    u8 payload[40 * 1200];
    for (unsigned int i = 0; i < sizeof(payload); i++)
        payload[i] = i % 251;
    struct msghdr message = {.msg_iter.bytes = payload};
    int before_sends = sends, before_allocations = allocations, before_requests = credit_requests,
        before_waits = waits;
    carrier_space = framed - 3;
    carrier[0] = 0xa5;
    assert(framed <= peer_capacity);
    assert(terra_send_udp(&state, &peer, &message, sizeof(payload), 1200, true) == -EAGAIN);
    assert(credit_requests == before_requests + 1 && sends == before_sends &&
           allocations == before_allocations);
    assert(message.msg_iter.bytes == payload && carrier[0] == 0xa5 && !transport.sk.locked);
    credit_request_error = -ENOMEM;
    assert(terra_send_udp(&state, &peer, &message, sizeof(payload), 1200, false) ==
           -ENOMEM);
    assert(credit_requests == before_requests + 2 && sends == before_sends &&
           allocations == before_allocations && waits == before_waits);
    assert(message.msg_iter.bytes == payload && carrier[0] == 0xa5 && !transport.sk.locked);
    credit_request_error = 0;
    requested_credit_space = peer_capacity;
    assert(terra_send_udp(&state, &peer, &message, sizeof(payload), 1200, false) ==
           (int)sizeof(payload));
    assert(credit_requests == before_requests + 3 && sends == before_sends + 1 &&
           allocations == before_allocations + 1);
    assert(waits == before_waits && !transport.sk.locked && !live_allocations);
    check_udp_frames(&peer, payload, sizeof(payload), 1200);
    requested_credit_space = -1;
    transport.sk.sk_state = TCP_CLOSE;
    assert(virtio_transport_send_credit_request(&transport) == -ENOTCONN);
    assert(credit_requests == before_requests + 3 && !transport.sk.locked);
}
static void udp_poll_checks(void) {
    struct vsock_sock transport = {.sk.sk_state = TCP_ESTABLISHED};
    struct sock outer = {0};
    struct proto_ops native = {.poll = carrier_poll};
    struct socket stream = {.sk = &transport.sk};
    struct socket socket = {.sk = &outer, .type = SOCK_DGRAM};
    poll_table wait = {0};
    struct terra_tsi_socket state = {
        .sk = &outer, .stream = &stream, .native_ops = &native, .mode = TERRA_SOCKET_EXTERNAL};
    outer.sk_user_data = &state;
    state_poll_registrations = 0;
    carrier_poll_mask = EPOLLOUT | EPOLLWRNORM;
    carrier_space = 0;
    assert(terra_socket_poll(NULL, &socket, &wait) == carrier_poll_mask);
    assert(state_poll_registrations == 1 && state_poll_queue == &state.wait);
    state.udp_open = true;
    assert(!terra_socket_poll(NULL, &socket, NULL) && state_poll_registrations == 1);
    carrier_space = TERRA_UDP_FRAME_BYTES;
    assert(terra_socket_poll(NULL, &socket, NULL) == carrier_poll_mask && state_poll_registrations == 1);
    carrier_space = 0;
    carrier_poll_mask = EPOLLIN;
    assert(terra_socket_poll(NULL, &socket, NULL) == EPOLLIN);
    carrier_poll_mask = 0;
    struct sk_buff datagram = {0};
    state.datagrams.first = &datagram;
    assert(terra_socket_poll(NULL, &socket, NULL) == (EPOLLIN | EPOLLRDNORM));
    state.datagrams.first = NULL;
    outer.sk_err = ENETDOWN;
    assert(terra_socket_poll(NULL, &socket, NULL) == EPOLLERR);
    assert(sock_error(&outer) == -ENETDOWN);
    state.udp_failed = -ENETDOWN;
    assert(terra_socket_poll(NULL, &socket, NULL) == (EPOLLERR | EPOLLHUP));
    assert(terra_socket_poll(NULL, &socket, NULL) == (EPOLLERR | EPOLLHUP));
}
static void tcp_close_checks(void) {
    struct vsock_sock transport = {.sk.sk_state = TCP_ESTABLISHED};
    struct sock outer = {0};
    struct proto_ops ops = {.poll = carrier_poll};
    struct socket socket = {.sk = &transport.sk, .ops = &ops}, original = {.sk = &outer, .type = SOCK_STREAM};
    struct terra_tsi_socket state = {
        .sk = &outer, .stream = &socket, .mode = TERRA_SOCKET_EXTERNAL, .connected = true};
    outer.sk_user_data = &state;
    carrier_poll_mask = EPOLLIN;
    transport.peer_shutdown = SEND_SHUTDOWN;
    terra_track_tcp_close(&state, &transport.sk);
    assert(state.peer_send_closed && !outer.sk_err);
    assert(terra_socket_poll(NULL, &original, NULL) == EPOLLIN);
    transport.peer_shutdown = SHUTDOWN_MASK;
    terra_track_tcp_close(&state, &transport.sk);
    assert(outer.sk_err == ECONNRESET && state.peer_closed);
    assert(terra_socket_poll(NULL, &original, NULL) & EPOLLERR);
    assert(sock_error(&outer) == -ECONNRESET);
    assert(terra_socket_poll(NULL, &original, NULL) == (EPOLLIN | EPOLLHUP));
    terra_track_tcp_close(&state, &transport.sk);
    assert(!outer.sk_err);
    assert(terra_socket_poll(NULL, &original, NULL) == (EPOLLIN | EPOLLHUP));
    state.peer_closed = false;
    transport.sk.sk_shutdown = SEND_SHUTDOWN;
    terra_track_tcp_close(&state, &transport.sk);
    assert(!outer.sk_err && state.peer_closed);
    state.peer_send_closed = false;
    state.peer_closed = false;
    transport.sk.sk_shutdown = 0;
    terra_track_tcp_close(&state, &transport.sk);
    assert(outer.sk_err == ECONNRESET);
    unsigned int stopped[] = {TCP_CLOSE, TCP_CLOSING};
    for (unsigned int i = 0; i < ARRAY_SIZE(stopped); i++) {
        state.connecting = true;
        transport.sk.sk_state = stopped[i];
        transport.sk.sk_err = 0;
        terra_setup_stream(&state.setup_work);
        assert(!state.connecting && state.connect_error == -ENETDOWN);
    }
    state.connecting = true;
    state.connect_error = 0;
    transport.sk.sk_state = TCP_SYN_SENT;
    terra_setup_stream(&state.setup_work);
    assert(state.connecting && !state.connect_error);
}
static struct sock *receive_outer;
static int carrier_receive(struct socket *socket, struct msghdr *message, size_t length, int flags) {
    (void)message;
    (void)length;
    (void)flags;
    assert(!terra_socket_state(receive_outer->sk_socket)->select_mutex.locked);
    socket->sk->sk_peek_off = 7;
    assert(!terra_set_peek_off(receive_outer, 11));
    return 2;
}
static void peek_mirror_checks(void) {
    struct sock outer = {.sk_peek_off = -1}, carrier_sock = {.sk_peek_off = -1};
    struct proto_ops native = {.set_peek_off = sk_set_peek_off, .recvmsg = native_receive};
    struct proto_ops transport = {.recvmsg = carrier_receive, .set_peek_off = carrier_set_peek_off};
    struct socket original = {.sk = &outer, .type = SOCK_STREAM},
                  stream = {.sk = &carrier_sock, .ops = &transport};
    struct terra_tsi_socket state = {.sk = &outer, .stream = &stream, .native_ops = &native};
    outer.sk_socket = &original;
    outer.sk_user_data = &state;
    receive_outer = &outer;
    assert(!terra_set_peek_off(&outer, 3) && outer.sk_peek_off == 3 && carrier_sock.sk_peek_off == -1);
    state.mode = TERRA_SOCKET_EXTERNAL;
    state.connecting = true;
    assert(!terra_set_peek_off(&outer, 5) && outer.sk_peek_off == 5 && carrier_sock.sk_peek_off == -1);
    carrier_sock.sk_state = TCP_ESTABLISHED;
    state.opened_needed = 32;
    state.opening_offset = TERRA_TCP_OPEN_BYTES;
    u8 opened[32] = {0x01, 0x01, 0, 0, 24, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0xbb, 1, 203, 0, 113, 1};
    memcpy(state.opened, opened, sizeof(opened));
    state.opened_length = 31;
    carrier_available = 1;
    carrier[0] = 0;
    terra_setup_stream(&state.setup_work);
    assert(!state.connecting && !state.connect_error && carrier_sock.sk_peek_off == 5);
    state.connected = true;
    peek_locked_carrier = &carrier_sock;
    assert(!terra_set_peek_off(&outer, 0) && !carrier_sock.sk_peek_off && !outer.sk_peek_off &&
           !carrier_sock.locked);
    struct msghdr message = {0};
    assert(receive_stream_once(&original, &message, 2, MSG_PEEK) == 2);
    assert(carrier_sock.sk_peek_off == 11 && outer.sk_peek_off == 11 && !state.select_mutex.locked);
    assert(!terra_set_peek_off(&outer, -1) && carrier_sock.sk_peek_off == -1 && outer.sk_peek_off == -1);
    state.mode = 0;
    native_result = 3;
    assert(receive_stream_once(&original, &message, 3, 0) == 3);
    assert(carrier_sock.sk_peek_off == -1 && outer.sk_peek_off == -1);
    peek_locked_carrier = NULL;
}
int main(void) {
    peer_checks();
    error_checks();
    opening_checks();
    udp_resume_checks();
    udp_checks();
    udp_control_checks();
    udp_receive_shutdown_checks();
    listen_selection_checks();
    udp_gso_checks();
    udp_atomic_credit_checks();
    udp_poll_checks();
    tcp_close_checks();
    peek_mirror_checks();
    udp_gro_checks();
    return 0;
}
