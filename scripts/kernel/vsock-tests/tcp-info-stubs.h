#ifndef TCP_INFO_STUBS_H
#define TCP_INFO_STUBS_H
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/udp.h>
typedef uint32_t u32;
typedef uint64_t u64;
#define __user
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOL_TCP 6
#define SOL_IP 0
#define SOL_IPV6 41
#define SOL_UDP 17
#define MSG_DONTWAIT 1
#define TCP_ESTABLISHED 1
#define TCP_FIN_WAIT2 5
#define TCP_CLOSE 7
#define TCP_CLOSE_WAIT 8
#define TERRA_SOCKET_EXTERNAL 2
#define TERRA_TCP_RECEIVE_BYTES 81920
#define TERRA_TCP_SEND_BYTES 49152
#define RCV_SHUTDOWN 1
#define SEND_SHUTDOWN 2
#define READ_ONCE(value) (value)
#define smp_load_acquire(value) (*(value))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))
#define max_t(type, a, b) ((type)(a) > (type)(b) ? (type)(a) : (type)(b))
#define get_user(value, pointer) ((pointer) ? ((value) = *(pointer), 0) : -EFAULT)
#define put_user(value, pointer) ((pointer) ? (*(pointer) = (value), 0) : -EFAULT)
static int copy_to_user(void *destination, const void *source, size_t length) {
    if (!destination)
        return 1;
    memcpy(destination, source, length);
    return 0;
}
struct mutex {
    bool locked;
};
static void mutex_lock(struct mutex *mutex) {
    assert(!mutex->locked);
    mutex->locked = true;
}
static void mutex_unlock(struct mutex *mutex) {
    assert(mutex->locked);
    mutex->locked = false;
}
struct tcp_sock {
    u64 bytes_sent, bytes_acked;
    struct {
        int user_mss;
    } rx_opt;
};
struct sock {
    int sk_err;
    unsigned int sk_shutdown;
    bool locked;
    struct tcp_sock tcp;
    void *sk_user_data;
};
struct virtio_vsock_sock {
    int tx_lock;
    u32 tx_cnt, peer_fwd_cnt, buf_alloc, peer_buf_alloc;
};
struct vsock_sock {
    struct sock sk;
    struct virtio_vsock_sock *trans;
};
static struct tcp_sock *tcp_sk(struct sock *sk) {
    return &sk->tcp;
}
static struct vsock_sock *vsock_sk(struct sock *sk) {
    return (struct vsock_sock *)sk;
}
struct socket;
struct msghdr {
    void *msg_name;
    unsigned int msg_namelen, msg_controllen;
    int msg_iter;
};
struct proto_ops {
    int (*sendmsg)(struct socket *, struct msghdr *, size_t);
    int (*getsockopt)(struct socket *, int, int, char *, int *);
};
struct socket {
    struct sock *sk;
    int type;
    const struct proto_ops *ops;
};
struct terra_tsi_socket {
    struct sock *sk;
    int mode;
    bool connected, connecting, udp_open;
    struct socket *stream;
    struct mutex select_mutex;
    const struct proto_ops *native_ops;
};
static struct sock *outer;
static void lock_sock(struct sock *sk) {
    assert(sk == outer && !sk->locked);
    sk->locked = true;
}
static void release_sock(struct sock *sk) {
    assert(sk == outer && sk->locked);
    sk->locked = false;
}
static void spin_lock_bh(int *lock) {
    assert(outer->locked && !*lock);
    *lock = 1;
}
static void spin_unlock_bh(int *lock) {
    assert(outer->locked && *lock);
    *lock = 0;
}
static struct terra_tsi_socket *terra_socket_state(struct socket *socket) {
    return socket->sk->sk_user_data;
}
static int sock_error(struct sock *sk) {
    int error = sk->sk_err;
    sk->sk_err = 0;
    return -error;
}
static int send_result, native_calls;
static bool reserved_before_return;
static int carrier_send(struct socket *socket, struct msghdr *message, size_t length) {
    assert(!outer->locked && !message->msg_name && !message->msg_namelen);
    (void)length;
    if (send_result > 0 && !reserved_before_return)
        vsock_sk(socket->sk)->trans->tx_cnt += send_result;
    message->msg_iter += send_result > 0 ? send_result : 0;
    return send_result;
}
static int native_send(struct socket *socket, struct msghdr *message, size_t length) {
    (void)socket;
    (void)message;
    (void)length;
    native_calls++;
    return send_result;
}
static int native_info(struct socket *socket, int level, int option, char *value, int *length) {
    (void)socket;
    (void)level;
    (void)option;
    (void)value;
    (void)length;
    native_calls++;
    return 17;
}
#endif
