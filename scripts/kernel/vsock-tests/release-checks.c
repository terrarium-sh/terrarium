#include "release-stubs.h"
#include "extracted.c"
int main(void) {
    struct proto_ops native = {.release = native_release};
    struct socket socket = {.sk = calloc(1, sizeof(struct sock)), .type = SOCK_STREAM};
    current = calloc(1, sizeof(*current));
    socket.sk->sk_user_data = current;
    current->sk = socket.sk;
    current->native_ops = &native;
    current->mode = TERRA_SOCKET_EXTERNAL;
    current->sk->sk_write_space = native_write_space;
    current->stream = calloc(1, sizeof(struct socket));
    current->stream->sk = calloc(1, sizeof(struct sock));
    current->stream->sk->sk_user_data = current;
    /* Queued skb completion can retain the callback after restore/orphan; the waitqueue needs the callback
     * lock. */
    struct socket_wq wait = {.wait = 123};
    callback_socket = current->stream->sk;
    callback_socket->sk_wq = &wait;
    terra_stream_callback(callback_socket);
    assert(carrier_wakes == 1 && outer_wakes == 1);
    current->sk->sk_type = SOCK_DGRAM;
    current->udp_open = true;
    callback_socket->sk_state = TCP_ESTABLISHED;
    for (int bytes = 0; bytes < TERRA_HEADER_BYTES; bytes++) {
        current->udp_work.queued = 0;
        callback_socket->vsock.available = bytes;
        terra_stream_callback(callback_socket);
        assert(!current->udp_work.queued);
    }
    current->udp_work.queued = 0;
    callback_socket->vsock.available = TERRA_HEADER_BYTES;
    terra_stream_callback(callback_socket);
    assert(current->udp_work.queued == 1);
    callback_socket->vsock.available = 0;
    current->udp_work.queued = 0;
    callback_socket->sk_err = 1;
    terra_stream_callback(callback_socket);
    assert(current->udp_work.queued == 1);
    callback_socket->sk_err = 0;
    current->udp_work.queued = 0;
    callback_socket->sk_state = TCP_CLOSE;
    terra_stream_callback(callback_socket);
    assert(current->udp_work.queued == 1);
    callback_socket->sk_state = TCP_ESTABLISHED;
    current->udp_work.queued = 0;
    callback_socket->sk_shutdown = RCV_SHUTDOWN;
    terra_stream_callback(callback_socket);
    assert(current->udp_work.queued == 1);
    callback_socket->sk_shutdown = 0;
    current->udp_work.queued = 0;
    callback_socket->vsock.peer_shutdown = SEND_SHUTDOWN;
    terra_stream_callback(callback_socket);
    assert(current->udp_work.queued == 1);
    assert(outer_wakes == 1 && state_wakes == TERRA_HEADER_BYTES + 5 &&
           state_wake_key == (EPOLLOUT | EPOLLWRNORM));
    current->sk->flags = SOCK_FASYNC;
    callback_socket->vsock.peer_shutdown = 0;
    current->udp_work.queued = 0;
    terra_stream_callback(callback_socket);
    assert(async_write_wakes == 1 && outer_wakes == 2 && state_wakes == TERRA_HEADER_BYTES + 6 &&
           !current->udp_work.queued);
    current->sk->flags = 0;
    current->sk->sk_type = SOCK_STREAM;
    callback_socket->vsock.peer_shutdown = 0;
    current->udp_work.queued = 0;
    current->connecting = true;
    terra_stream_callback(callback_socket);
    assert(current->setup_work.queued == 1 && outer_wakes == 3);
    current->setup_work.queued = 0;
    current->connecting = false;
    carrier_wakes = 1;
    outer_wakes = 1;
    current->closing = true;
    terra_stream_callback(callback_socket);
    assert(carrier_wakes == 2 && outer_wakes == 1);
    assert(state_wakes == TERRA_HEADER_BYTES + 6);
    callback_socket->sk_user_data = NULL;
    callback_socket->sk_wq = NULL;
    terra_stream_callback(callback_socket);
    assert(carrier_wakes == 2 && outer_wakes == 1);
    callback_socket->sk_wq = &wait;
    orphan_on_unlock = callback_socket;
    terra_stream_callback(callback_socket);
    assert(carrier_wakes == 3 && !callback_socket->sk_wq);
    callback_socket->sk_user_data = current;
    callback_inflight = true;
    assert(!terra_release_socket(&socket) && !socket.sk && !callback_inflight);
    return 0;
}
