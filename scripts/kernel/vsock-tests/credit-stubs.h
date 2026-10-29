#ifndef CREDIT_STUBS_H
#define CREDIT_STUBS_H
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
typedef uint16_t u16;
typedef uint32_t u32;
typedef int64_t s64;
#define SOCK_STREAM 1
#define SOCK_SEQPACKET 5
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2
#define TCP_CLOSING 11
#define VIRTIO_VSOCK_OP_RST 3
#define VIRTIO_VSOCK_OP_SHUTDOWN 4
#define VIRTIO_VSOCK_OP_RW 5
#define VIRTIO_VSOCK_OP_CREDIT_UPDATE 6
#define VIRTIO_VSOCK_OP_CREDIT_REQUEST 7
#define VIRTIO_VSOCK_SHUTDOWN_SEND 2
#define MSG_PEEK 2
#define MSG_TRUNC 4
#define SEND_SHUTDOWN 2
#define RCV_SHUTDOWN 1
#define READ_ONCE(value) (value)
#define WRITE_ONCE(target, value) ((target) = (value))
#define TASK_INTERRUPTIBLE 1
#define EXPORT_SYMBOL_GPL(symbol)
#define WARN_ONCE(condition, message) (condition)
#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))
#define max_t(type, a, b) ((type)(a) > (type)(b) ? (type)(a) : (type)(b))
#define le16_to_cpu(value) (value)
#define le32_to_cpu(value) (value)
#define cpu_to_le32(value) (value)
struct test_lock {
    int id;
    bool held;
};
struct sk_buff;
struct sk_buff_head {
    struct sk_buff *first, *last;
};
struct virtio_vsock_sock {
    struct test_lock tx_lock, rx_lock;
    u32 tx_cnt, peer_fwd_cnt, peer_buf_alloc, fwd_cnt, last_fwd_cnt, rx_bytes, buf_alloc, buf_used;
    struct sk_buff_head rx_queue;
};
struct sock {
    int sk_state, sk_type, sk_rcvlowat, sk_err, sk_peek_off;
    unsigned int sk_shutdown;
};
struct vsock_sock;
struct vsock_transport_recv_notify_data {
    int unused;
};
struct vsock_transport {
    int (*notify_recv_pre_block)(struct vsock_sock *, size_t, struct vsock_transport_recv_notify_data *);
};
struct vsock_sock {
    struct sock sk;
    struct virtio_vsock_sock *trans;
    const struct vsock_transport *transport;
    unsigned int peer_shutdown;
};
struct virtio_vsock_hdr {
    u32 buf_alloc, fwd_cnt, flags, len;
    u16 op;
};
struct sk_buff {
    struct virtio_vsock_hdr header;
    struct sk_buff *next;
    u32 len;
    char bytes[64];
    struct {
        u32 offset;
    } cb;
};
struct msghdr {
    struct iov_iter {
        char *bytes;
        size_t copied;
    } msg_iter;
};
struct wait_queue_entry {
    int unused;
};
#define VIRTIO_VSOCK_SKB_CB(skb) (&(skb)->cb)
#define skb_queue_walk(queue, skb) for ((skb) = (queue)->first; (skb); (skb) = (skb)->next)
static bool skb_queue_empty(struct sk_buff_head *queue) {
    return !queue->first;
}
static struct sk_buff *skb_peek(struct sk_buff_head *queue) {
    return queue->first;
}
static void __skb_unlink(struct sk_buff *skb, struct sk_buff_head *queue) {
    assert(queue->first == skb);
    queue->first = skb->next;
    if (!queue->first)
        queue->last = NULL;
}
static int copies, copy_failure, dequeued_skbs;
static void consume_skb(struct sk_buff *skb) {
    (void)skb;
    dequeued_skbs++;
}
static int held_lock, updates, lock_order;
static bool socket_locked = true;
static void spin_lock_bh(struct test_lock *lock) {
    assert(socket_locked && !held_lock && !lock->held);
    held_lock = lock->id;
    lock->held = true;
    lock_order = (lock_order % 10000000) * 10 + lock->id;
}
static void spin_unlock_bh(struct test_lock *lock) {
    assert(held_lock == lock->id && lock->held);
    held_lock = 0;
    lock->held = false;
}
static struct sock *sk_vsock(struct vsock_sock *vsk) {
    return &vsk->sk;
}
static struct vsock_sock *vsock_sk(struct sock *sk) {
    return (struct vsock_sock *)sk;
}
static int sk_peek_offset(struct sock *sk, int flags) {
    return flags & MSG_PEEK ? sk->sk_peek_off : 0;
}
static void sk_peek_offset_bwd(struct sock *sk, int bytes) {
    int offset = sk->sk_peek_off;
    if (offset >= 0)
        sk->sk_peek_off = max(offset - bytes, 0);
}
static void sk_peek_offset_fwd(struct sock *sk, int bytes) {
    sk_peek_offset_bwd(sk, -bytes);
}
static int sk_set_peek_off(struct sock *sk, int offset) {
    assert(socket_locked);
    sk->sk_peek_off = offset;
    return 0;
}
static int skb_copy_datagram_iter(struct sk_buff *skb, size_t offset, struct iov_iter *iter, size_t bytes) {
    assert(socket_locked && !held_lock && offset + bytes <= skb->len);
    copies++;
    if (copies == copy_failure || !iter->bytes)
        return -EFAULT;
    memcpy(iter->bytes + iter->copied, skb->bytes + offset, bytes);
    iter->copied += bytes;
    return 0;
}
static struct virtio_vsock_hdr *virtio_vsock_hdr(struct sk_buff *skb) {
    return &skb->header;
}
static int sock_rcvlowat(struct sock *sk, int waitall, int length) {
    (void)waitall;
    return min(sk->sk_rcvlowat ? sk->sk_rcvlowat : 1, length);
}
static bool virtio_transport_has_space(struct virtio_vsock_sock *vvs) {
    assert(held_lock == vvs->tx_lock.id);
    return min(vvs->buf_alloc, vvs->peer_buf_alloc) > vvs->tx_cnt - vvs->peer_fwd_cnt;
}
/* Upstream virtio_transport_common.c helpers the patch leaves unchanged. */
static void virtio_transport_dec_rx_pkt(struct virtio_vsock_sock *vvs, u32 bytes_read, u32 bytes_dequeued) {
    vvs->rx_bytes -= bytes_read;
    vvs->buf_used -= bytes_dequeued;
    vvs->fwd_cnt += bytes_dequeued;
}
static void virtio_transport_inc_tx_pkt(struct virtio_vsock_sock *vvs, struct sk_buff *skb) {
    struct virtio_vsock_hdr *hdr = virtio_vsock_hdr(skb);
    spin_lock_bh(&vvs->rx_lock);
    vvs->last_fwd_cnt = vvs->fwd_cnt;
    hdr->fwd_cnt = cpu_to_le32(vvs->fwd_cnt);
    hdr->buf_alloc = cpu_to_le32(vvs->buf_alloc);
    spin_unlock_bh(&vvs->rx_lock);
}
static int virtio_transport_send_credit_update(struct vsock_sock *vsk) {
    assert(socket_locked && !held_lock && !vsk->trans->tx_lock.held && !vsk->trans->rx_lock.held);
    struct sk_buff packet = {0};
    updates++;
    virtio_transport_inc_tx_pkt(vsk->trans, &packet);
    assert(packet.header.fwd_cnt == vsk->trans->fwd_cnt && packet.header.buf_alloc == vsk->trans->buf_alloc);
    return 0;
}
static void initialize(struct vsock_sock *vsk, struct virtio_vsock_sock *vvs, u32 local, u32 peer) {
    memset(vsk, 0, sizeof(*vsk));
    memset(vvs, 0, sizeof(*vvs));
    vsk->sk = (struct sock){.sk_state = TCP_ESTABLISHED, .sk_type = SOCK_STREAM, .sk_rcvlowat = 1};
    vsk->trans = vvs;
    vvs->buf_alloc = local;
    vvs->peer_buf_alloc = peer;
    vvs->tx_lock.id = 1;
    vvs->rx_lock.id = 2;
    held_lock = 0;
    updates = 0;
    lock_order = 0;
    copies = 0;
    copy_failure = 0;
    dequeued_skbs = 0;
    vsk->sk.sk_peek_off = -1;
}
static int pre_blocks, sleeps, wait_action, forced_data_error;
static int notify_before_block(struct vsock_sock *vsk, size_t target,
                               struct vsock_transport_recv_notify_data *data) {
    assert(socket_locked && !held_lock);
    (void)vsk;
    (void)target;
    (void)data;
    pre_blocks++;
    return 0;
}
static const struct vsock_transport stream_transport = {.notify_recv_pre_block = notify_before_block};
static struct vsock_sock *waiting_vsk;
static s64 vsock_connectible_has_data(struct vsock_sock *vsk) {
    return forced_data_error ? forced_data_error : vsk->trans->rx_bytes;
}
static void *sk_sleep(struct sock *sk) {
    (void)sk;
    return NULL;
}
static void prepare_to_wait(void *queue, struct wait_queue_entry *wait, int state) {
    (void)queue;
    (void)wait;
    (void)state;
    assert(socket_locked);
}
static void finish_wait(void *queue, struct wait_queue_entry *wait) {
    (void)queue;
    (void)wait;
    assert(socket_locked);
}
static void release_sock(struct sock *sk) {
    (void)sk;
    assert(socket_locked);
    socket_locked = false;
}
static void lock_sock(struct sock *sk) {
    (void)sk;
    assert(!socket_locked);
    socket_locked = true;
}
static int signal_pending(void *task) {
    (void)task;
    return wait_action == 3;
}
static void *current;
static int sock_intr_errno(long timeout) {
    (void)timeout;
    return -EINTR;
}
static long schedule_timeout(long timeout) {
    assert(!socket_locked && !held_lock && timeout > 0);
    sleeps++;
    if (wait_action == 1) {
        struct sk_buff *skb = waiting_vsk->trans->rx_queue.last;
        assert(skb);
        skb->bytes[skb->len++] = 'Z';
        skb->header.len++;
        waiting_vsk->trans->rx_bytes++;
        waiting_vsk->trans->buf_used++;
        wait_action = 0;
        return timeout - 1;
    }
    if (wait_action == 2) {
        waiting_vsk->peer_shutdown = SEND_SHUTDOWN;
        return timeout - 1;
    }
    return wait_action == 3 ? timeout - 1 : 0;
}
#endif
