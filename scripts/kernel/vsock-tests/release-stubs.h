#ifndef RELEASE_STUBS_H
#define RELEASE_STUBS_H
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/epoll.h>
#define WRITE_ONCE(target, value) ((target) = (value))
#define READ_ONCE(value) (value)
#define rcu_access_pointer(value) (value)
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_FASYNC 1
#define TCP_CLOSE 0
#define TCP_ESTABLISHED 1
#define RCV_SHUTDOWN 1
#define SEND_SHUTDOWN 2
#define TERRA_HEADER_BYTES 8
#define TERRA_SOCKET_EXTERNAL 2
#define smp_load_acquire(value) (*(value))
struct socket;
struct proto_ops {
    int (*release)(struct socket *);
};
struct socket_wq {
    int wait;
};
struct vsock_sock {
    long long available;
    int peer_shutdown;
};
struct sock {
    void *sk_user_data;
    int sk_callback_lock, sk_state, sk_type, sk_err, sk_shutdown;
    struct socket_wq *sk_wq;
    unsigned int flags;
    struct vsock_sock vsock;
    void (*sk_data_ready)(struct sock *), (*sk_write_space)(struct sock *);
    void (*sk_state_change)(struct sock *), (*sk_error_report)(struct sock *);
};
struct socket {
    struct sock *sk;
    const struct proto_ops *ops;
    int type;
};
struct work_struct {
    int queued;
};
struct delayed_work {
    struct work_struct work;
};
struct terra_tsi_socket {
    struct socket *stream;
    struct sock *sk;
    const struct proto_ops *native_ops;
    bool closing, connecting, udp_open;
    int mode;
    struct delayed_work timeout_work;
    struct work_struct setup_work, udp_work;
    int datagrams, wait;
    void *udp_frame, *udp_receive;
    void (*data_ready)(struct sock *), (*write_space)(struct sock *);
    void (*state_change)(struct sock *), (*error_report)(struct sock *);
};
static struct terra_tsi_socket *current;
static bool callback_inflight;
static struct sock *orphan_on_unlock, *callback_socket;
static int carrier_wakes, outer_wakes, state_wakes, async_write_wakes;
static unsigned int state_wake_key;
static void read_lock_bh(int *lock) {
    assert(!*lock);
    *lock = 1;
}
static void read_unlock_bh(int *lock) {
    assert(*lock);
    *lock = 0;
    if (orphan_on_unlock) {
        orphan_on_unlock->sk_wq = NULL;
        orphan_on_unlock = NULL;
    }
}
static int *sk_sleep(struct sock *socket) {
    return socket->sk_wq ? &socket->sk_wq->wait : NULL;
}
static void wake_up_interruptible_all(int *wait) {
    assert(wait && *wait == 123 && callback_socket->sk_callback_lock);
    carrier_wakes++;
}
static void wake_up_interruptible_poll(int *wait, unsigned int key) {
    assert(wait == &current->wait && callback_socket->sk_callback_lock);
    assert(key == (EPOLLOUT | EPOLLWRNORM));
    state_wakes++;
    state_wake_key = key;
}
static bool sock_flag(struct sock *socket, unsigned int flag) {
    return socket->flags & flag;
}
static void native_write_space(struct sock *socket) {
    assert(socket == current->sk && sock_flag(socket, SOCK_FASYNC) && callback_socket->sk_callback_lock);
    async_write_wakes++;
    outer_wakes++;
}
static struct vsock_sock *vsock_sk(struct sock *socket) {
    return &socket->vsock;
}
static long long vsock_stream_has_data(struct vsock_sock *socket) {
    return socket->available;
}
static void *system_unbound_wq;
static void queue_work(void *queue, struct work_struct *work) {
    (void)queue;
    work->queued++;
}
static void terra_track_tcp_close(struct terra_tsi_socket *state, struct sock *socket) {
    (void)state;
    (void)socket;
}
static void terra_socket_wake(struct terra_tsi_socket *state) {
    assert(state && !state->closing);
    outer_wakes++;
}
static void write_lock_bh(int *lock) {
    assert(!*lock);
    *lock = 1;
    if (callback_inflight) {
        callback_inflight = false;
        current->udp_work.queued = 1;
    }
}
static void write_unlock_bh(int *lock) {
    assert(*lock);
    *lock = 0;
}
static void cancel_work_sync(struct work_struct *work) {
    work->queued = 0;
}
static void cancel_delayed_work_sync(struct delayed_work *work) {
    cancel_work_sync(&work->work);
}
static struct terra_tsi_socket *terra_socket_state(struct socket *socket) {
    return socket->sk->sk_user_data;
}
static void lock_sock(struct sock *socket) {
    (void)socket;
}
static void release_sock(struct sock *socket) {
    (void)socket;
}
static void skb_queue_purge(int *queue) {
    (void)queue;
}
#define kfree free
#define rcu_assign_sk_user_data(socket, value) ((socket)->sk_user_data = (value))
static void sock_release(struct socket *stream) {
    assert(!callback_inflight && !current->udp_work.queued && !current->setup_work.queued);
    assert(!stream->sk->sk_user_data);
    free(stream->sk);
    free(stream);
}
static int native_release(struct socket *socket) {
    assert(socket->sk->sk_state == TCP_CLOSE && !socket->sk->sk_user_data);
    free(socket->sk);
    socket->sk = NULL;
    return 0;
}
#endif
