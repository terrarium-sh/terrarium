#include "credit-stubs.h"
#include "extracted.c"
static void queue_receive(struct vsock_sock *vsk, struct virtio_vsock_sock *vvs, struct sk_buff *first,
                          struct sk_buff *second) {
    initialize(vsk, vvs, 16, 16);
    vsk->transport = &stream_transport;
    memset(first, 0, sizeof(*first));
    memset(second, 0, sizeof(*second));
    first->len = first->header.len = 3;
    memcpy(first->bytes, "abc", 3);
    first->next = second;
    second->len = second->header.len = 5;
    memcpy(second->bytes, "defgh", 5);
    vvs->rx_queue = (struct sk_buff_head){.first = first, .last = second};
    vvs->rx_bytes = vvs->buf_used = 8;
    waiting_vsk = vsk;
    pre_blocks = sleeps = wait_action = forced_data_error = 0;
}
static void stream_receive_checks(void) {
    struct vsock_sock vsk;
    struct virtio_vsock_sock vvs;
    struct sk_buff first, second;
    char bytes[32] = {0};
    struct msghdr message = {.msg_iter.bytes = bytes};
    queue_receive(&vsk, &vvs, &first, &second);
    socket_locked = false;
    assert(!vsock_set_peek_off(&vsk.sk, 0) && !socket_locked && !vsk.sk.sk_peek_off);
    lock_sock(&vsk.sk);
    vsk.sk.sk_peek_off = -1;
    assert(virtio_transport_stream_dequeue(&vsk, &message, 3, MSG_PEEK) == 3);
    assert(!memcmp(bytes, "abc", 3) && vsk.sk.sk_peek_off == -1 && vvs.rx_bytes == 8 && !vvs.fwd_cnt &&
           !dequeued_skbs);
    message.msg_iter.copied = 0;
    assert(virtio_transport_stream_dequeue(&vsk, &message, 3, MSG_PEEK) == 3);
    assert(!memcmp(bytes, "abc", 3) && vsk.sk.sk_peek_off == -1);
    vsk.sk.sk_peek_off = 0;
    message.msg_iter.copied = 0;
    assert(virtio_transport_stream_dequeue(&vsk, &message, 3, MSG_PEEK) == 3 && vsk.sk.sk_peek_off == 3);
    message.msg_iter.copied = 0;
    assert(virtio_transport_stream_dequeue(&vsk, &message, 3, MSG_PEEK) == 3 && vsk.sk.sk_peek_off == 6);
    assert(!memcmp(bytes, "def", 3) && !vvs.fwd_cnt && vvs.rx_bytes == 8);
    message.msg_iter.copied = 0;
    assert(virtio_transport_stream_dequeue(&vsk, &message, 2, 0) == 2 && vsk.sk.sk_peek_off == 4);
    assert(!memcmp(bytes, "ab", 2) && first.cb.offset == 2 && vvs.rx_bytes == 6 && vvs.buf_used == 8 &&
           !vvs.fwd_cnt);
    message.msg_iter.bytes = NULL;
    int before = copies;
    assert(virtio_transport_stream_dequeue(&vsk, &message, 2, MSG_TRUNC) == 2 && vsk.sk.sk_peek_off == 2);
    assert(copies == before && vvs.rx_bytes == 4 && vvs.buf_used == 5 && vvs.fwd_cnt == 3 &&
           dequeued_skbs == 1 && !updates);
    assert(virtio_transport_stream_dequeue(&vsk, &message, 2, MSG_PEEK | MSG_TRUNC) == 2 &&
           vsk.sk.sk_peek_off == 4);
    assert(copies == before && vvs.rx_bytes == 4 && vvs.fwd_cnt == 3 && dequeued_skbs == 1);
    assert(virtio_transport_stream_dequeue(&vsk, &message, 4, MSG_TRUNC) == 4 && !vsk.sk.sk_peek_off);
    assert(copies == before && !vvs.rx_bytes && !vvs.buf_used && vvs.fwd_cnt == 8 && updates == 1 &&
           dequeued_skbs == 2);

    queue_receive(&vsk, &vvs, &first, &second);
    vsk.sk.sk_peek_off = 5;
    message = (struct msghdr){.msg_iter.bytes = bytes};
    assert(virtio_transport_stream_dequeue(&vsk, &message, 2, MSG_PEEK) == 2 && !memcmp(bytes, "fg", 2));
    assert(vsk.sk.sk_peek_off == 7 && vvs.rx_bytes == 8 && !vvs.fwd_cnt);
    queue_receive(&vsk, &vvs, &first, &second);
    vsk.sk.sk_peek_off = 0;
    copy_failure = 2;
    message = (struct msghdr){.msg_iter.bytes = bytes};
    assert(virtio_transport_stream_dequeue(&vsk, &message, 8, MSG_PEEK) == 3 && vsk.sk.sk_peek_off == 3);
    assert(vvs.rx_bytes == 8 && !vvs.fwd_cnt && !held_lock);
    queue_receive(&vsk, &vvs, &first, &second);
    vsk.sk.sk_peek_off = 7;
    copy_failure = 2;
    message = (struct msghdr){.msg_iter.bytes = bytes};
    assert(virtio_transport_stream_dequeue(&vsk, &message, 8, 0) == 3 && vsk.sk.sk_peek_off == 4);
    assert(vvs.rx_bytes == 5 && vvs.buf_used == 5 && vvs.fwd_cnt == 3 && !held_lock);
    queue_receive(&vsk, &vvs, &first, &second);
    copy_failure = 1;
    message.msg_iter.copied = 0;
    assert(virtio_transport_stream_dequeue(&vsk, &message, 1, MSG_PEEK) == -EFAULT &&
           vsk.sk.sk_peek_off == -1);
    assert(vvs.rx_bytes == 8 && !vvs.fwd_cnt && !held_lock);

    struct wait_queue_entry wait = {0};
    struct vsock_transport_recv_notify_data notify = {0};
    queue_receive(&vsk, &vvs, &first, &second);
    vsk.sk.sk_peek_off = 8;
    assert(vsock_connectible_wait_data(&vsk.sk, &wait, 0, &notify, 1, MSG_PEEK) == -EAGAIN);
    assert(!sleeps && !pre_blocks && vvs.rx_bytes == 8 && vsk.sk.sk_peek_off == 8);
    assert(vsock_connectible_wait_data(&vsk.sk, &wait, 0, &notify, 1, 0) == 8);
    wait_action = 1;
    assert(vsock_connectible_wait_data(&vsk.sk, &wait, 5, &notify, 1, MSG_PEEK) == 1);
    assert(sleeps == 1 && pre_blocks == 1 && socket_locked && vsk.sk.sk_peek_off == 8);
    message = (struct msghdr){.msg_iter.bytes = bytes};
    assert(virtio_transport_stream_dequeue(&vsk, &message, 1, MSG_PEEK) == 1 && bytes[0] == 'Z' &&
           vsk.sk.sk_peek_off == 9);
    vsk.peer_shutdown = SEND_SHUTDOWN;
    assert(!vsock_connectible_wait_data(&vsk.sk, &wait, 0, &notify, 1, MSG_PEEK));
    vsk.peer_shutdown = 0;
    vsk.sk.sk_peek_off = INT_MAX;
    assert(vsock_connectible_wait_data(&vsk.sk, &wait, 0, &notify, 1, MSG_PEEK) == -EAGAIN);
    wait_action = 2;
    assert(!vsock_connectible_wait_data(&vsk.sk, &wait, 5, &notify, 1, MSG_PEEK));
    vsk.peer_shutdown = 0;
    wait_action = 0;
    assert(vsock_connectible_wait_data(&vsk.sk, &wait, 5, &notify, 1, MSG_PEEK) == -EAGAIN);
    wait_action = 3;
    assert(vsock_connectible_wait_data(&vsk.sk, &wait, 5, &notify, 1, MSG_PEEK) == -EINTR);
    vsk.sk.sk_type = SOCK_SEQPACKET;
    assert(vsock_connectible_wait_data(&vsk.sk, &wait, 0, NULL, 0, 0) == 9);
    assert(socket_locked && !held_lock);
}

int main(void) {
    struct vsock_sock socket;
    struct virtio_vsock_sock vvs;
    struct sk_buff shrink = {.header = {.buf_alloc = 4096, .op = VIRTIO_VSOCK_OP_CREDIT_UPDATE}};
    initialize(&socket, &vvs, 24576, 49152);
    vvs.fwd_cnt = 1228;
    check_dequeue_credit(&socket);
    assert(!updates && vvs.last_fwd_cnt == 0 && lock_order == 12);
    vvs.fwd_cnt = 12287;
    lock_order = 0;
    check_dequeue_credit(&socket);
    assert(!updates);
    vvs.fwd_cnt = 12288;
    lock_order = 0;
    check_dequeue_credit(&socket);
    assert(updates == 1 && vvs.last_fwd_cnt == 12288);
    vvs.fwd_cnt = 24576;
    lock_order = 0;
    check_dequeue_credit(&socket);
    assert(updates == 2);

    initialize(&socket, &vvs, 81920, 8192);
    vvs.fwd_cnt = 4095;
    check_dequeue_credit(&socket);
    assert(!updates);
    lock_order = 0;
    vvs.fwd_cnt = 4096;
    check_dequeue_credit(&socket);
    assert(updates == 1);
    initialize(&socket, &vvs, 4096, 24576);
    vvs.fwd_cnt = 2048;
    check_dequeue_credit(&socket);
    assert(updates == 1);
    initialize(&socket, &vvs, 1, 1);
    vvs.fwd_cnt = 1;
    check_dequeue_credit(&socket);
    assert(updates == 1);

    initialize(&socket, &vvs, 24576, 49152);
    socket.sk.sk_rcvlowat = 21504;
    vvs.rx_bytes = 20480;
    vvs.fwd_cnt = 4096;
    check_dequeue_credit(&socket);
    assert(updates == 1);
    initialize(&socket, &vvs, 24576, 49152);
    vvs.rx_bytes = 4096;
    vvs.buf_used = 4096;
    spin_lock_bh(&vvs.rx_lock);
    virtio_transport_dec_rx_pkt(&vvs, 1024, 0);
    spin_unlock_bh(&vvs.rx_lock);
    assert(vvs.rx_bytes == 3072 && vvs.buf_used == 4096 && !vvs.fwd_cnt);
    check_dequeue_credit(&socket);
    assert(!updates);
    spin_lock_bh(&vvs.rx_lock);
    virtio_transport_dec_rx_pkt(&vvs, 3072, 4096);
    spin_unlock_bh(&vvs.rx_lock);
    assert(!vvs.rx_bytes && !vvs.buf_used && vvs.fwd_cnt == 4096);
    lock_order = 0;
    check_dequeue_credit(&socket);
    assert(!updates);
    struct sk_buff piggyback = {0};
    virtio_transport_inc_tx_pkt(&vvs, &piggyback);
    assert(vvs.last_fwd_cnt == 4096 && piggyback.header.fwd_cnt == 4096 &&
           piggyback.header.buf_alloc == 24576);
    lock_order = 0;
    check_dequeue_credit(&socket);
    assert(!updates);
    initialize(&socket, &vvs, 8192, 8192);
    vvs.last_fwd_cnt = UINT32_MAX - 4095;
    vvs.fwd_cnt = 0;
    check_dequeue_credit(&socket);
    assert(updates == 1);

    initialize(&socket, &vvs, 24576, 24576);
    vvs.fwd_cnt = 4096;
    check_dequeue_credit(&socket);
    assert(!updates);
    lock_order = 0;
    virtio_transport_space_update(&socket.sk, &shrink);
    assert(updates == 1 && vvs.peer_buf_alloc == 4096 && vvs.last_fwd_cnt == 4096 && lock_order == 122);
    lock_order = 0;
    virtio_transport_space_update(&socket.sk, &shrink);
    assert(updates == 1);
    initialize(&socket, &vvs, 24576, 24576);
    virtio_transport_space_update(&socket.sk, &shrink);
    assert(!updates);
    initialize(&socket, &vvs, 24576, 4096);
    vvs.fwd_cnt = 4096;
    shrink.header.buf_alloc = 8192;
    virtio_transport_space_update(&socket.sk, &shrink);
    assert(!updates);
    shrink.header.buf_alloc = 4096;

    const int states[] = {TCP_SYN_SENT, TCP_CLOSING};
    for (unsigned int i = 0; i < sizeof(states) / sizeof(states[0]); i++) {
        initialize(&socket, &vvs, 24576, 24576);
        vvs.fwd_cnt = 4096;
        socket.sk.sk_state = states[i];
        virtio_transport_space_update(&socket.sk, &shrink);
        assert(!updates);
    }
    initialize(&socket, &vvs, 24576, 24576);
    vvs.fwd_cnt = 4096;
    socket.sk.sk_type = SOCK_SEQPACKET;
    virtio_transport_space_update(&socket.sk, &shrink);
    assert(!updates);
    initialize(&socket, &vvs, 24576, 24576);
    socket.trans = NULL;
    assert(virtio_transport_space_update(&socket.sk, &shrink) && !updates);
    const u16 excluded[] = {0, VIRTIO_VSOCK_OP_RST, VIRTIO_VSOCK_OP_CREDIT_REQUEST};
    for (unsigned int i = 0; i < sizeof(excluded) / sizeof(excluded[0]); i++) {
        initialize(&socket, &vvs, 24576, 24576);
        vvs.fwd_cnt = 4096;
        shrink.header.op = excluded[i];
        virtio_transport_space_update(&socket.sk, &shrink);
        assert(!updates);
    }
    initialize(&socket, &vvs, 24576, 24576);
    vvs.fwd_cnt = 4096;
    shrink.header.op = VIRTIO_VSOCK_OP_RW;
    virtio_transport_space_update(&socket.sk, &shrink);
    assert(updates == 1);
    initialize(&socket, &vvs, 24576, 24576);
    vvs.fwd_cnt = 4096;
    shrink.header.op = VIRTIO_VSOCK_OP_SHUTDOWN;
    shrink.header.flags = VIRTIO_VSOCK_SHUTDOWN_SEND;
    virtio_transport_space_update(&socket.sk, &shrink);
    assert(!updates);
    initialize(&socket, &vvs, 24576, 24576);
    vvs.fwd_cnt = 4096;
    shrink.header.flags = 0;
    virtio_transport_space_update(&socket.sk, &shrink);
    assert(updates == 1);
    assert(!held_lock);
    stream_receive_checks();
    return 0;
}
