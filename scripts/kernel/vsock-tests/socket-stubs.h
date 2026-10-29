#ifndef SOCKET_STUBS_H
#define SOCKET_STUBS_H
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;
typedef unsigned int __poll_t;
typedef struct poll_table poll_table;
struct poll_table {
    int marker;
};
struct file;
typedef uint16_t __be16;
typedef uint32_t __be32;
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define min(a, b) ((a) < (b) ? (a) : (b))
#define min_t(type, a, b) min((type)(a), (type)(b))
#define max_t(type, a, b) ((type)(a) > (type)(b) ? (type)(a) : (type)(b))
#define DIV_ROUND_UP(value, divisor) (((value) + (divisor) - 1) / (divisor))
#define READ_ONCE(x) (x)
#define WRITE_ONCE(target, value) ((target) = (value))
#define xchg(target, value)                                                                                  \
    ({                                                                                                       \
        __typeof__(*(target)) old = *(target);                                                               \
        *(target) = (value);                                                                                 \
        old;                                                                                                 \
    })
#define SHUT_RDWR 2
#define SEND_SHUTDOWN 2
#define RCV_SHUTDOWN 1
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT 2
#define TCP_CLOSE 7
#define TCP_CLOSING 11
#define SS_CONNECTED 3
#define SHUTDOWN_MASK 3
#define MSG_DONTWAIT 1
#define MSG_PEEK 2
#define MSG_NOSIGNAL 4
#define MSG_ERRQUEUE 8
#define MSG_TRUNC 0x20
#define SOL_SOCKET 1
#define SOL_IP 2
#define SOL_IPV6 3
#define SOL_UDP 17
#define SO_RCVBUF 1
#define SO_SNDBUF 2
#define IP_RECVERR 3
#define IP_TTL 4
#define IPV6_RECVERR 5
#define IP_TOS 6
#define IPV6_TCLASS 7
#define IP_PKTINFO 8
#define IPV6_PKTINFO 9
#define UDP_SEGMENT 103
#define UDP_GRO 104
#define U16_MAX 65535
#define GFP_KERNEL 0
#define AF_INET 2
#define AF_INET6 10
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define TERRA_SOCKET_EXTERNAL 2
#define TERRA_SOCKET_NATIVE 1
#define VIRTIO_VSOCK_OP_CREDIT_REQUEST 7
#define EXPORT_SYMBOL_GPL(name)
#define smp_load_acquire(value) (*(value))
#define container_of(p, t, m) ((t *)((char *)(p) - offsetof(t, m)))
static u16 htons(u16 value) {
    return __builtin_bswap16(value);
}
static u16 ntohs(u16 value) {
    return __builtin_bswap16(value);
}
static u32 htonl(u32 value) {
    return __builtin_bswap32(value);
}
static u16 get_unaligned_le16(const void *p) {
    const u8 *b = p;
    return b[0] | b[1] << 8;
}
static u32 get_unaligned_le32(const void *p) {
    const u8 *b = p;
    return b[0] | b[1] << 8 | b[2] << 16 | (u32)b[3] << 24;
}
static void put_unaligned_le16(u16 v, void *p) {
    u8 *b = p;
    b[0] = v;
    b[1] = v >> 8;
}
static void put_unaligned_le32(u32 v, void *p) {
    u8 *b = p;
    b[0] = v;
    b[1] = v >> 8;
    b[2] = v >> 16;
    b[3] = v >> 24;
}
struct in_addr {
    __be32 s_addr;
};
struct in6_addr {
    union {
        u8 s6_addr[16];
        __be32 s6_addr32[4];
    };
};
struct sockaddr_storage {
    u16 ss_family;
    u8 padding[126];
};
struct sockaddr {
    u16 sa_family;
};
struct sockaddr_in {
    u16 sin_family;
    __be16 sin_port;
    struct in_addr sin_addr;
    u8 padding[8];
};
struct sockaddr_in6 {
    u16 sin6_family;
    __be16 sin6_port;
    u32 sin6_flowinfo;
    struct in6_addr sin6_addr;
    u32 sin6_scope_id;
};
static bool ipv6_addr_v4mapped(const struct in6_addr *a) {
    return !a->s6_addr32[0] && !a->s6_addr32[1] && a->s6_addr32[2] == htonl(0xffff);
}
static bool ipv6_addr_equal(const struct in6_addr *a, const struct in6_addr *b) {
    return !memcmp(a, b, 16);
}
static bool ipv6_addr_any(const struct in6_addr *a) {
    return !(a->s6_addr32[0] | a->s6_addr32[1] | a->s6_addr32[2] | a->s6_addr32[3]);
}
static void ipv6_addr_set_v4mapped(__be32 address, struct in6_addr *mapped) {
    *mapped = (struct in6_addr){.s6_addr32 = {0, 0, htonl(0xffff), address}};
}
static const void *memchr_inv(const void *start, int value, size_t length) {
    for (const u8 *byte = start; length--; byte++)
        if (*byte != (u8)value)
            return byte;
    return NULL;
}
struct in_pktinfo {
    int ipi_ifindex;
    struct in_addr ipi_spec_dst, ipi_addr;
};
struct in6_pktinfo {
    struct in6_addr ipi6_addr;
    unsigned int ipi6_ifindex;
};
struct work_struct {
    int queued;
};
struct delayed_work {
    struct work_struct work;
};
struct mutex {
    int locked;
};
static void mutex_lock(struct mutex *m) {
    assert(!m->locked);
    m->locked = 1;
}
static void mutex_unlock(struct mutex *m) {
    assert(m->locked);
    m->locked = 0;
}
static int select_lock_error;
static void (*select_lock_hook)(void);
static int mutex_lock_interruptible(struct mutex *m) {
    if (select_lock_error)
        return select_lock_error;
    if (select_lock_hook) {
        select_lock_hook();
        select_lock_hook = NULL;
    }
    mutex_lock(m);
    return 0;
}
#define to_delayed_work(work) container_of(work, struct delayed_work, work)
#define time_before(first, second) ((long)((second) - (first)) > 0)
static unsigned long jiffies, timeout_delay;
static void *system_unbound_wq;
static void mod_delayed_work(void *queue, struct delayed_work *work, unsigned long delay) {
    (void)queue;
    work->work.queued++;
    timeout_delay = delay;
}
static void cancel_delayed_work(struct delayed_work *work) {
    work->work.queued = 0;
}
static void queue_work(void *queue, struct work_struct *work) {
    (void)queue;
    work->queued++;
}
struct sock {
    int sk_err, sk_state;
    unsigned int sk_shutdown;
    void *sk_user_data;
    int sk_peek_off;
    struct socket *sk_socket;
    bool locked;
    void (*sk_data_ready)(struct sock *);
    int sk_family;
    struct in6_addr sk_v6_rcv_saddr, sk_v6_daddr;
    struct udp_sock {
        u16 gso_size;
        bool gro_enabled;
    } udp;
    struct inet_sock {
        __be32 inet_rcv_saddr;
    } inet;
    int sk_rmem_alloc, sk_rcvbuf;
};
#define udp_test_bit(bit, sk) ((sk)->udp.gro_enabled)
#define atomic_read(value) (*(value))
static struct udp_sock *udp_sk(struct sock *sk) {
    return &sk->udp;
}
static struct inet_sock *inet_sk(struct sock *sk) {
    return &sk->inet;
}
struct virtio_vsock_sock {
    int tx_lock;
    u32 buf_alloc, peer_buf_alloc;
};
static void spin_lock_bh(int *lock) {
    assert(!*lock);
    *lock = 1;
}
static void spin_unlock_bh(int *lock) {
    assert(*lock);
    *lock = 0;
}
struct vsock_sock {
    struct sock sk;
    unsigned int peer_shutdown;
    struct virtio_vsock_sock *trans;
};
#define vsock_sk(socket) container_of(socket, struct vsock_sock, sk)
#define sk_vsock(socket) (&(socket)->sk)
struct virtio_vsock_pkt_info {
    u16 op;
    struct vsock_sock *vsk;
};
struct socket;
struct msghdr;
struct proto_ops {
    int (*listen)(struct socket *, int);
    int (*connect)(struct socket *, struct sockaddr *, int, int);
    __poll_t (*poll)(struct file *, struct socket *, poll_table *);
    int (*recvmsg)(struct socket *, struct msghdr *, size_t, int);
    int (*set_peek_off)(struct sock *, int);
};
struct socket {
    struct sock *sk;
    int state, type;
    const struct proto_ops *ops;
    struct file *file;
};
struct kvec {
    void *iov_base;
    size_t iov_len;
};
struct msghdr {
    unsigned int msg_flags;
    int msg_namelen;
    struct iov_iter {
        const u8 *bytes;
    } msg_iter;
    void *msg_control;
    size_t msg_controllen;
};
struct cmsghdr {
    size_t cmsg_len;
    int cmsg_level, cmsg_type;
};
#define CMSG_ALIGN(length) (((length) + sizeof(size_t) - 1) & ~(sizeof(size_t) - 1))
#define CMSG_LEN(length) (CMSG_ALIGN(sizeof(struct cmsghdr)) + (length))
#define CMSG_SPACE(length) CMSG_ALIGN(CMSG_LEN(length))
#define CMSG_DATA(control) ((u8 *)(control) + CMSG_LEN(0))
#define CMSG_FIRSTHDR(message)                                                                               \
    ((message)->msg_controllen >= sizeof(struct cmsghdr) ? (struct cmsghdr *)(message)->msg_control : NULL)
#define CMSG_OK(message, control)                                                                            \
    ((control)->cmsg_len >= sizeof(struct cmsghdr) &&                                                        \
     (control)->cmsg_len <= (message)->msg_controllen - ((u8 *)(control) - (u8 *)(message)->msg_control))
static struct cmsghdr *next_cmsg(struct msghdr *message, struct cmsghdr *control) {
    size_t offset = (u8 *)control - (u8 *)message->msg_control;
    size_t advance = CMSG_ALIGN(control->cmsg_len);
    return advance + sizeof(*control) <= message->msg_controllen - offset ? (void *)((u8 *)control + advance)
                                                                          : NULL;
}
#define for_each_cmsghdr(control, message)                                                                   \
    for ((control) = CMSG_FIRSTHDR(message); (control); (control) = next_cmsg(message, control))
static int allocations, live_allocations;
static bool allocation_fails;
static void *kmalloc(size_t length, int flags) {
    (void)flags;
    allocations++;
    if (allocation_fails)
        return NULL;
    live_allocations++;
    return malloc(length);
}
static void kfree(void *bytes) {
    assert(live_allocations > 0);
    live_allocations--;
    free(bytes);
}
#define kvmalloc(length, flags) kmalloc(length, flags)
#define kvfree(bytes) kfree(bytes)
#define MAX_SKB_FRAGS 17
#define PAGE_ALLOC_COSTLY_ORDER 3
#define __GFP_NOWARN 0
#define PAGE_ALIGN(length) (((length) + 4095UL) & ~4095UL)
#define SKB_TRUESIZE(length) ((length) + 256)
typedef struct {
    u8 *page;
    unsigned int off, size;
} skb_frag_t;
struct skb_shared_info {
    unsigned int nr_frags;
    skb_frag_t frags[MAX_SKB_FRAGS];
};
struct sk_buff {
    struct sk_buff *next;
    unsigned int len, data_len, truesize;
    int users;
    u8 cb[48];
    struct skb_shared_info shinfo;
    u8 data[4116];
};
#define skb_shinfo(skb) (&(skb)->shinfo)
static u8 *skb_frag_page(const skb_frag_t *fragment) {
    return fragment->page;
}
static unsigned int skb_frag_off(const skb_frag_t *fragment) {
    return fragment->off;
}
static unsigned int skb_frag_size(const skb_frag_t *fragment) {
    return fragment->size;
}
#define page_address(page) (page)
static bool skb_allocation_fails;
static struct sk_buff *alloc_skb_with_frags(unsigned long header_length, unsigned long data_length, int order,
                                            int *error, int flags) {
    (void)order;
    (void)flags;
    assert(header_length <= 4116);
    if (skb_allocation_fails) {
        *error = -ENOBUFS;
        return NULL;
    }
    struct sk_buff *skb = calloc(1, sizeof(*skb));
    skb->users = 1;
    skb->truesize = SKB_TRUESIZE(header_length);
    for (unsigned long offset = 0; offset < data_length; offset += 4096) {
        skb_frag_t *fragment = &skb->shinfo.frags[skb->shinfo.nr_frags++];
        assert(skb->shinfo.nr_frags <= MAX_SKB_FRAGS);
        fragment->size = data_length - offset < 4096 ? data_length - offset : 4096;
        fragment->page = malloc(fragment->size);
        skb->truesize += 4096;
    }
    return skb;
}
static u8 *skb_put(struct sk_buff *skb, unsigned int length) {
    assert(!skb->data_len);
    u8 *tail = skb->data + skb->len;
    skb->len += length;
    return tail;
}
static u8 skb_byte(const struct sk_buff *skb, unsigned int offset) {
    unsigned int linear = skb->len - skb->data_len;
    if (offset < linear)
        return skb->data[offset];
    offset -= linear;
    return skb->shinfo.frags[offset / 4096].page[offset % 4096];
}
static void skb_get(struct sk_buff *skb) {
    skb->users++;
}
struct sk_buff_head {
    struct sk_buff *first, *last;
    unsigned int qlen;
    int lock;
};
static bool skb_queue_empty(struct sk_buff_head *queue) {
    return !queue->first;
}
static struct sk_buff *alloc_skb(unsigned int length, int flags) {
    assert(length <= 4116);
    (void)flags;
    struct sk_buff *skb = calloc(1, sizeof(struct sk_buff));
    skb->users = 1;
    return skb;
}
static void skb_put_data(struct sk_buff *skb, const void *bytes, unsigned int length) {
    memcpy(skb->data, bytes, length);
    skb->len = length;
}
static void skb_queue_tail(struct sk_buff_head *queue, struct sk_buff *skb) {
    if (queue->last)
        queue->last->next = skb;
    else
        queue->first = skb;
    queue->last = skb;
    queue->qlen++;
}
static struct sk_buff *skb_peek(struct sk_buff_head *queue) {
    assert(queue->lock);
    return queue->first;
}
static void __skb_unlink(struct sk_buff *skb, struct sk_buff_head *queue) {
    assert(queue->lock && queue->first == skb);
    queue->first = skb->next;
    queue->last = queue->first ? queue->last : NULL;
    queue->qlen--;
    skb->next = NULL;
}
static void kfree_skb(struct sk_buff *skb) {
    if (--skb->users) {
        return;
    }
    for (unsigned int index = 0; index < skb->shinfo.nr_frags; index++)
        free(skb->shinfo.frags[index].page);
    free(skb);
}
static u8 received[65536];
static size_t received_length, iter_receive_limit = SIZE_MAX;
static int skb_copy_datagram_iter(const struct sk_buff *skb, int offset, struct iov_iter *destination,
                                  int length) {
    (void)destination;
    assert(offset >= 0 && length >= 0 && (unsigned int)(offset + length) <= skb->len);
    if ((size_t)length > iter_receive_limit)
        return -EFAULT;
    iter_receive_limit -= length;
    for (int index = 0; index < length; index++)
        received[received_length++] = skb_byte(skb, offset + index);
    return 0;
}
#define skb_queue_walk(queue, skb) for ((skb) = (queue)->first; (skb); (skb) = (skb)->next)
static int gro_cmsgs, gro_segment;
static int put_cmsg(struct msghdr *message, int level, int type, int length, void *data) {
    (void)message;
    assert(level == SOL_UDP && type == UDP_GRO && length == sizeof(int));
    gro_cmsgs++;
    memcpy(&gro_segment, data, sizeof(int));
    return 0;
}
static int shutdowns;
static int kernel_sock_shutdown(struct socket *socket, int how) {
    (void)socket;
    (void)how;
    shutdowns++;
    return 0;
}
#define TERRA_HEADER_BYTES 8
#define TERRA_ENDPOINT_BYTES 20
#define TERRA_OP_TCP_OPENED 0x101
#define TERRA_OP_UDP_SEND 0x03
#define TERRA_OP_UDP_DATAGRAM 0x103
#define TERRA_OP_UDP_ERROR 0x104
#define TERRA_UDP_DATAGRAM 4096
#define TERRA_UDP_FRAME_BYTES (TERRA_HEADER_BYTES + TERRA_ENDPOINT_BYTES + 4 + TERRA_UDP_DATAGRAM)
struct terra_tsi_socket {
    u8 opened[64];
    unsigned int opened_needed;
    struct mutex select_mutex;
    struct delayed_work timeout_work;
    struct socket *stream;
    unsigned long opening_deadline;
    bool connecting, closing;
    int connect_error;
    struct sock *sk;
    struct sockaddr_in6 peer;
    int udp_failed, wait;
    u8 *udp_frame;
    struct sk_buff_head datagrams;
    bool peer_send_closed, peer_closed, connected, udp_open;
    int mode;
    const struct proto_ops *native_ops;
    struct work_struct setup_work, udp_work;
    u8 opening[64];
    unsigned int opening_offset, opened_length;
};
/* terra_connect_locked is compiled whole; the checks drive only its early branches, so its later steps abort.
 */
#define AF_UNSPEC 0
#define TERRA_SOCKET_UNSELECTED 0
#define smp_store_release(pointer, value) (*(pointer) = (value))
static const struct in6_addr in6addr_any;
static int terra_tsi_select_native(struct socket *socket, struct sockaddr *peer, int length) {
    (void)socket;
    (void)peer;
    (void)length;
    abort();
}
static void terra_detach_stream(struct terra_tsi_socket *state) {
    (void)state;
    abort();
}
static int terra_copy_peer(struct sockaddr_in6 *peer, const struct sockaddr *address, int length) {
    (void)peer;
    (void)address;
    (void)length;
    abort();
}
static int terra_bind_external(struct terra_tsi_socket *state) {
    (void)state;
    abort();
}
static int terra_udp_open(struct terra_tsi_socket *state) {
    (void)state;
    abort();
}
static void terra_set_udp_peer(struct terra_tsi_socket *state) {
    (void)state;
    abort();
}
static int terra_begin_stream(struct terra_tsi_socket *state) {
    (void)state;
    abort();
}
static int terra_wait_connected(struct terra_tsi_socket *state, int flags) {
    (void)state;
    (void)flags;
    abort();
}
static void terra_finish_opening(struct terra_tsi_socket *state, int error) {
    state->connecting = false;
    state->connect_error = error;
}
static __poll_t carrier_poll_mask;
static __poll_t carrier_poll(struct file *file, struct socket *socket, poll_table *wait) {
    (void)file;
    (void)socket;
    (void)wait;
    return carrier_poll_mask;
}
static void sock_poll_wait(struct file *file, struct socket *socket, poll_table *wait) {
    (void)file;
    (void)socket;
    (void)wait;
}
static int state_poll_registrations;
static int *state_poll_queue;
static void poll_wait(struct file *file, int *queue, poll_table *wait) {
    (void)file;
    if (wait) {
        state_poll_registrations++;
        state_poll_queue = queue;
    }
}
static struct terra_tsi_socket *terra_socket_state(struct socket *socket) {
    return socket->sk->sk_user_data;
}
static struct sock *peek_locked_carrier;
static int sk_set_peek_off(struct sock *sk, int offset) {
    if (sk == peek_locked_carrier)
        assert(sk->locked);
    WRITE_ONCE(sk->sk_peek_off, offset);
    return 0;
}
static void lock_sock(struct sock *sk) {
    assert(!sk->locked);
    sk->locked = true;
}
static void release_sock(struct sock *sk) {
    assert(sk->locked);
    sk->locked = false;
}
static int carrier_set_peek_off(struct sock *sk, int offset) {
    lock_sock(sk);
    int result = sk_set_peek_off(sk, offset);
    release_sock(sk);
    return result;
}
static void terra_stream_options(struct terra_tsi_socket *state) {
    (void)state;
}
static int native_result, native_receive_flags, native_receive_calls;
static int native_receive(struct socket *socket, struct msghdr *message, size_t length, int flags) {
    (void)socket;
    (void)message;
    (void)length;
    native_receive_flags = flags;
    native_receive_calls++;
    return native_result;
}
static int wakes, queued_errors, sends, waits, wait_action;
static struct sock *waiting_socket;
static u8 carrier[270000];
static s64 carrier_available, carrier_space;
static int credit_requests, credit_request_error;
static s64 requested_credit_space = -1;
static int virtio_transport_send_pkt_info(struct vsock_sock *socket, struct virtio_vsock_pkt_info *info) {
    assert(socket->sk.locked && !socket->trans->tx_lock);
    assert(info->vsk == socket && info->op == VIRTIO_VSOCK_OP_CREDIT_REQUEST);
    credit_requests++;
    if (!credit_request_error && requested_credit_space >= 0)
        carrier_space = requested_credit_space;
    return credit_request_error;
}
static s64 vsock_stream_has_data(struct vsock_sock *sk) {
    (void)sk;
    return carrier_available;
}
static s64 vsock_stream_has_space(struct vsock_sock *sk) {
    (void)sk;
    return carrier_space;
}
static int kernel_recvmsg(struct socket *socket, struct msghdr *message, struct kvec *vector,
                          unsigned int count, size_t length, int flags) {
    (void)socket;
    (void)message;
    size_t total = 0, offset = 0;
    for (unsigned int index = 0; index < count; index++)
        total += vector[index].iov_len;
    assert(length == total);
    if (!carrier_available)
        return -EAGAIN;
    assert(carrier_available >= (s64)length);
    for (unsigned int index = 0; index < count && !(flags & MSG_TRUNC); index++) {
        memcpy(vector[index].iov_base, carrier + offset, vector[index].iov_len);
        offset += vector[index].iov_len;
    }
    if (!(flags & MSG_PEEK)) {
        carrier_available -= length;
        memmove(carrier, carrier + length, carrier_available);
    }
    return length;
}
static int kernel_sendmsg(struct socket *socket, struct msghdr *message, struct kvec *vector,
                          unsigned int count, size_t length) {
    (void)socket;
    (void)message;
    assert(count == 1 && length == vector->iov_len);
    sends++;
    assert(length <= sizeof(carrier));
    memcpy(carrier, vector->iov_base, length);
    return length;
}
static void terra_socket_wake(struct terra_tsi_socket *state) {
    (void)state;
    wakes++;
}
static int decoded_data_wakes;
static void decoded_data_ready(struct sock *sk) {
    assert(sk);
    decoded_data_wakes++;
}
static void terra_socket_error(struct terra_tsi_socket *state, int error) {
    state->sk->sk_err = -error;
    terra_socket_wake(state);
}
static void terra_queue_datagram_error(struct terra_tsi_socket *state, int error,
                                       const struct sockaddr_in6 *peer) {
    (void)state;
    assert(error == -EACCES && ipv6_addr_v4mapped(&peer->sin6_addr));
    queued_errors++;
}
static void terra_udp_failed(struct terra_tsi_socket *state, int error) {
    state->udp_failed = error;
    terra_socket_error(state, error);
}
static int sock_error(struct sock *socket) {
    int error = socket->sk_err;
    socket->sk_err = 0;
    return -error;
}
static long sock_sndtimeo(struct sock *socket, bool nonblock) {
    (void)socket;
    return nonblock ? 0 : 30;
}
static int sock_intr_errno(long timeout) {
    (void)timeout;
    return -EINTR;
}
static size_t iter_copy_limit = SIZE_MAX;
static bool copy_from_iter_full(void *destination, size_t length, struct iov_iter *source) {
    if (length > iter_copy_limit)
        return false;
    iter_copy_limit -= length;
    memcpy(destination, source->bytes, length);
    source->bytes += length;
    return true;
}
static void apply_wait_event(void) {
    waits++;
    if (wait_action == 1)
        waiting_socket->sk_shutdown = SEND_SHUTDOWN;
    else if (wait_action == 2)
        waiting_socket->sk_err = EACCES;
    else
        carrier_space = 10000;
}
#define wait_event_interruptible_timeout(queue, condition, timeout)                                          \
    ({                                                                                                       \
        assert((queue) == 123);                                                                              \
        (void)(timeout);                                                                                     \
        if (!(condition)) {                                                                                  \
            apply_wait_event();                                                                              \
            assert(condition);                                                                               \
        }                                                                                                    \
        1L;                                                                                                  \
    })
#endif
