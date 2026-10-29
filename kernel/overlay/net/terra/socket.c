// SPDX-License-Identifier: GPL-2.0-only
#include <linux/build_bug.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kobject.h>
#include <asm/ioctls.h>
#include <linux/net.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/splice.h>
#include <linux/sysfs.h>
#include <linux/terra_socket.h>
#include <linux/uaccess.h>
#include <linux/udp.h>
#include <linux/unaligned.h>
#include <linux/vm_sockets.h>
#include <linux/virtio_vsock.h>
#include <net/af_vsock.h>
#include <net/net_namespace.h>
#include <net/inet_sock.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/ipv6.h>
#include <net/sock.h>
#include <net/sock_reuseport.h>
#include <uapi/linux/sockios.h>

#define TERRA_SOCKET_VERSION 1
#define TERRA_NETWORK_VERSION 1
#define TERRA_HEADER_BYTES 8
#define TERRA_ENDPOINT_BYTES 20
/* TCP_OPEN: header, version, target kind, flags, three keepalive fields, then the peer endpoint. */
#define TERRA_TCP_OPEN_BYTES (TERRA_HEADER_BYTES + 12 + TERRA_ENDPOINT_BYTES)
#define TERRA_TCP_PORT 6002
#define TERRA_UDP_PORT 6003
#define TERRA_TCP_SEGMENT_BYTES 65535
#define TERRA_TCP_RECEIVE_BYTES 81920
#define TERRA_TCP_SEND_BYTES 49152
static_assert(TERRA_TCP_RECEIVE_BYTES + TERRA_TCP_SEND_BYTES == 131072);
#define TERRA_UDP_DATAGRAM 4096
#define TERRA_UDP_MAX_SEGMENTS 64
#define TERRA_UDP_SEGMENT_FIELD_BYTES 4
/* A UDP frame is header, peer endpoint, and segment field, then datagram payload. */
#define TERRA_UDP_PREFIX_BYTES \
	(TERRA_HEADER_BYTES + TERRA_ENDPOINT_BYTES + TERRA_UDP_SEGMENT_FIELD_BYTES)
#define TERRA_UDP_FRAME_BYTES (TERRA_UDP_PREFIX_BYTES + TERRA_UDP_DATAGRAM)
#define TERRA_UDP_CARRIER_BYTES 65536
/*
 * A UDP frame fills at most the carrier's buffer; a larger one could never be fully received.
 * terra_send_udp's capacity check enforces this bound with -EMSGSIZE, as native GSO does.
 */
#define TERRA_UDP_RUN_BYTES (TERRA_UDP_CARRIER_BYTES - TERRA_UDP_PREFIX_BYTES)
#define TERRA_UDP_QUEUE_BYTES 131072
#define TERRA_UDP_QUEUED_DATAGRAMS 48
#define TERRA_DRAIN_BUDGET 16
#define TERRA_OPEN_TIMEOUT (30 * HZ)

#define TERRA_OP_TCP_OPEN 0x01
#define TERRA_OP_UDP_OPEN 0x02
#define TERRA_OP_UDP_SEND 0x03
#define TERRA_OP_TCP_OPENED 0x101
#define TERRA_OP_UDP_OPENED 0x102
#define TERRA_OP_UDP_DATAGRAM 0x103
#define TERRA_OP_UDP_ERROR 0x104

/* A queued skb's payload came from `peer`; its first `offset` bytes were already delivered. */
struct terra_datagram_cb {
	struct sockaddr_in6 peer;
	u32 offset;
	u16 segment;
};

#define TERRA_DATAGRAM_CB(skb) ((struct terra_datagram_cb *)(skb)->cb)
static_assert(sizeof(struct terra_datagram_cb) <= sizeof_field(struct sk_buff, cb));

static unsigned int terra_datagram_bytes(const struct sk_buff *skb)
{
	return skb->len - TERRA_DATAGRAM_CB(skb)->offset;
}

/* Size of the skb's next datagram; every later one but a shorter last has the same size. */
static unsigned int terra_datagram_segment(const struct sk_buff *skb)
{
	unsigned int bytes = terra_datagram_bytes(skb), segment = TERRA_DATAGRAM_CB(skb)->segment;

	return segment && segment < bytes ? segment : bytes;
}

enum terra_socket_mode {
	TERRA_SOCKET_UNSELECTED,
	TERRA_SOCKET_NATIVE,
	TERRA_SOCKET_EXTERNAL,
};

struct terra_tsi_socket {
	struct socket *socket;
	struct sock *sk;
	const struct proto_ops *native_ops;
	struct proto_ops operations;
	struct socket *stream;
	/* Guards mode, peer, the carrier stream, and the TCP opening exchange. */
	struct mutex select_mutex;
	/* Serializes connect and external UDP sends, which share udp_frame and carrier space. */
	struct mutex send_mutex;
	/* Serializes UDP receives, which peek, copy, then consume the head datagram. */
	struct mutex receive_mutex;
	struct work_struct setup_work;
	struct delayed_work timeout_work;
	struct work_struct udp_work;
	wait_queue_head_t wait;
	/* The external peer; an IPv4 one is v4-mapped so both families compare and encode alike. */
	struct sockaddr_in6 peer;
	enum terra_socket_mode mode;
	/*
	 * connecting, connected, and udp_open are set with smp_store_release after the stream and
	 * connect_error they describe; lockless readers pair them with smp_load_acquire.
	 */
	bool connecting;
	bool connected;
	bool closing;
	bool udp_open;
	bool peer_send_closed;
	bool peer_closed;
	int udp_failed;
	int connect_error;
	u8 opening[TERRA_TCP_OPEN_BYTES];
	u8 opened[TERRA_HEADER_BYTES + 4 + TERRA_ENDPOINT_BYTES];
	unsigned int opening_offset;
	unsigned int opened_length;
	unsigned int opened_needed;
	unsigned long opening_deadline;
	void (*data_ready)(struct sock *sk);
	void (*write_space)(struct sock *sk);
	void (*state_change)(struct sock *sk);
	void (*error_report)(struct sock *sk);
	struct sk_buff_head datagrams;
	u8 *udp_frame;
};

static struct terra_tsi_socket *terra_socket_state(struct socket *socket)
{
	return (void *)((uintptr_t)READ_ONCE(socket->sk->sk_user_data) & SK_USER_DATA_PTRMASK);
}

/* The errno for each terra_protocol::socket::Error code; code 0 is success, not an error. */
static const u8 terra_errors[] = {
	0, EACCES, EINVAL, ENOTCONN, ESTALE, EPROTOTYPE, EAGAIN,
	ENOBUFS, EALREADY, ECANCELED, ECONNREFUSED, ECONNRESET, ETIMEDOUT, EHOSTUNREACH,
	EAGAIN, EMSGSIZE, EPIPE, EIO, EOPNOTSUPP, ENETDOWN, EPROTO,
};

static int terra_decode_error(u16 status)
{
	return status && status < ARRAY_SIZE(terra_errors) ? -terra_errors[status] : -EPROTO;
}

static void terra_socket_wake(struct terra_tsi_socket *state)
{
	wake_up_interruptible(&state->wait);
	state->sk->sk_data_ready(state->sk);
	state->sk->sk_write_space(state->sk);
}

static void terra_socket_error(struct terra_tsi_socket *state, int error)
{
	WRITE_ONCE(state->sk->sk_err, error < 0 ? -error : error);
	state->sk->sk_error_report(state->sk);
	terra_socket_wake(state);
}

static void terra_queue_datagram_error(struct terra_tsi_socket *state, int error,
				       const struct sockaddr_in6 *peer)
{
	struct flowi6 flow = { .daddr = peer->sin6_addr, .fl6_dport = peer->sin6_port };
	struct sock *sk = state->sk;

	if (sk->sk_family == AF_INET ||
	    (ipv6_addr_v4mapped(&peer->sin6_addr) && inet_test_bit(RECVERR, sk) &&
	     !inet6_test_bit(RECVERR6, sk)))
		ip_local_error(sk, -error, peer->sin6_addr.s6_addr32[3], peer->sin6_port, 0);
	else
		ipv6_local_error(sk, -error, &flow, 0);
}

static int terra_encode_peer(u8 *endpoint, const struct sockaddr_in6 *peer)
{
	memset(endpoint, 0, TERRA_ENDPOINT_BYTES);
	if (peer->sin6_scope_id || peer->sin6_flowinfo)
		return -EOPNOTSUPP;
	if (!peer->sin6_port)
		return -EINVAL;
	put_unaligned_le16(ntohs(peer->sin6_port), endpoint + 2);
	if (ipv6_addr_v4mapped(&peer->sin6_addr)) {
		endpoint[0] = 4;
		memcpy(endpoint + 4, &peer->sin6_addr.s6_addr32[3], 4);
	} else {
		endpoint[0] = 6;
		memcpy(endpoint + 4, &peer->sin6_addr, 16);
	}
	return 0;
}

static int terra_decode_peer(struct sockaddr_in6 *peer, const u8 *endpoint)
{
	__be32 address4;

	memset(peer, 0, sizeof(*peer));
	peer->sin6_family = AF_INET6;
	peer->sin6_port = htons(get_unaligned_le16(endpoint + 2));
	if (endpoint[1])
		return -EPROTO;
	if (endpoint[0] == 6) {
		memcpy(&peer->sin6_addr, endpoint + 4, 16);
		return 0;
	}
	if (endpoint[0] != 4 || memchr_inv(endpoint + 8, 0, TERRA_ENDPOINT_BYTES - 8))
		return -EPROTO;
	memcpy(&address4, endpoint + 4, sizeof(address4));
	ipv6_addr_set_v4mapped(address4, &peer->sin6_addr);
	return 0;
}

static bool terra_peer_equal(const struct sockaddr_in6 *first, const struct sockaddr_in6 *second)
{
	return first->sin6_port == second->sin6_port &&
		ipv6_addr_equal(&first->sin6_addr, &second->sin6_addr);
}

/* Writes `peer` in the form the socket's family reports addresses and returns its length. */
static int terra_report_peer(const struct sock *sk, const struct sockaddr_in6 *peer, void *address)
{
	struct sockaddr_in *address4 = address;

	if (sk->sk_family == AF_INET6) {
		memcpy(address, peer, sizeof(*peer));
		return sizeof(*peer);
	}
	memset(address4, 0, sizeof(*address4));
	address4->sin_family = AF_INET;
	address4->sin_port = peer->sin6_port;
	address4->sin_addr.s_addr = peer->sin6_addr.s6_addr32[3];
	return sizeof(*address4);
}

static int terra_copy_peer(struct sockaddr_in6 *peer, const struct sockaddr *address, int length)
{
	const struct sockaddr_in *address4 = (const void *)address;

	memset(peer, 0, sizeof(*peer));
	if (length < sizeof(address->sa_family))
		return -EINVAL;
	switch (address->sa_family) {
	case AF_INET:
		if (length < sizeof(*address4))
			return -EINVAL;
		peer->sin6_family = AF_INET6;
		peer->sin6_port = address4->sin_port;
		ipv6_addr_set_v4mapped(address4->sin_addr.s_addr, &peer->sin6_addr);
		return 0;
	case AF_INET6:
		if (length < SIN6_LEN_RFC2133)
			return -EINVAL;
		memcpy(peer, address, min_t(int, length, sizeof(*peer)));
		return 0;
	default:
		return -EAFNOSUPPORT;
	}
}

/* Gives the native socket a local port before external use, as connect or sendto would. */
static int terra_bind_external(struct terra_tsi_socket *state)
{
	struct sockaddr_storage local = { .ss_family = state->sk->sk_family };

	if (inet_sk(state->sk)->inet_num)
		return 0;
	return state->native_ops->bind(state->socket, (struct sockaddr_unsized *)&local,
		state->sk->sk_family == AF_INET ? sizeof(struct sockaddr_in) :
						 sizeof(struct sockaddr_in6));
}

static void terra_frame_header(u8 *bytes, u16 opcode, unsigned int length)
{
	put_unaligned_le16(opcode, bytes);
	put_unaligned_le16(0, bytes + 2);
	put_unaligned_le32(length, bytes + 4);
}

static int terra_set_peek_off(struct sock *sk, int offset)
{
	struct terra_tsi_socket *state = terra_socket_state(sk->sk_socket);
	int error;

	mutex_lock(&state->select_mutex);
	if (state->mode == TERRA_SOCKET_EXTERNAL && smp_load_acquire(&state->connected)) {
		error = state->stream->ops->set_peek_off(state->stream->sk, offset);
		if (!error)
			sk_set_peek_off(sk, offset);
	} else {
		error = state->native_ops->set_peek_off(sk, offset);
	}
	mutex_unlock(&state->select_mutex);
	return error;
}

static void terra_stream_options(struct terra_tsi_socket *state)
{
	struct sock *transport = state->stream->sk;
	u64 buffer = clamp_t(u64, READ_ONCE(state->sk->sk_rcvbuf), 128, TERRA_TCP_RECEIVE_BYTES);

	WRITE_ONCE(transport->sk_sndtimeo, READ_ONCE(state->sk->sk_sndtimeo));
	WRITE_ONCE(transport->sk_rcvtimeo, READ_ONCE(state->sk->sk_rcvtimeo));
	WRITE_ONCE(transport->sk_rcvlowat, READ_ONCE(state->sk->sk_rcvlowat));
	WRITE_ONCE(transport->sk_sndbuf,
		   min_t(int, READ_ONCE(state->sk->sk_sndbuf), TERRA_TCP_SEND_BYTES));
	state->stream->ops->setsockopt(state->stream, AF_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE,
		KERNEL_SOCKPTR(&buffer), sizeof(buffer));
}

static int terra_create_stream(struct terra_tsi_socket *state, u64 receive_bytes)
{
	struct sockaddr_vm local = {
		.svm_family = AF_VSOCK, .svm_cid = 3, .svm_port = VMADDR_PORT_ANY,
	};
	sockptr_t value = KERNEL_SOCKPTR(&receive_bytes);
	u32 port;
	int error;

	error = sock_create_kern(&init_net, AF_VSOCK, SOCK_STREAM, 0, &state->stream);
	if (error)
		return error;
	error = kernel_bind(state->stream, (struct sockaddr_unsized *)&local, sizeof(local));
	port = vsock_sk(state->stream->sk)->local_addr.svm_port;
	/* A dynamic carrier port must not shadow Terra's fixed vsock ports 6000-6004. */
	if (!error && port >= 6000 && port <= 6004)
		error = -EADDRNOTAVAIL;
	if (!error)
		error = state->stream->ops->setsockopt(state->stream, AF_VSOCK,
						       SO_VM_SOCKETS_BUFFER_MAX_SIZE, value,
						       sizeof(receive_bytes));
	if (!error)
		error = state->stream->ops->setsockopt(state->stream, AF_VSOCK,
						       SO_VM_SOCKETS_BUFFER_SIZE, value,
						       sizeof(receive_bytes));
	if (error) {
		sock_release(state->stream);
		state->stream = NULL;
	}
	return error;
}

static void terra_stream_callback(struct sock *sk);

static void terra_attach_callbacks(struct terra_tsi_socket *state)
{
	struct sock *sk = state->stream->sk;

	write_lock_bh(&sk->sk_callback_lock);
	state->data_ready = sk->sk_data_ready;
	state->write_space = sk->sk_write_space;
	state->state_change = sk->sk_state_change;
	state->error_report = sk->sk_error_report;
	sk->sk_user_data = state;
	sk->sk_data_ready = terra_stream_callback;
	sk->sk_write_space = terra_stream_callback;
	sk->sk_state_change = terra_stream_callback;
	sk->sk_error_report = terra_stream_callback;
	write_unlock_bh(&sk->sk_callback_lock);
}

static void terra_restore_stream_callbacks(struct terra_tsi_socket *state)
{
	struct sock *sk;

	if (!state->stream)
		return;
	sk = state->stream->sk;
	write_lock_bh(&sk->sk_callback_lock);
	if (sk->sk_user_data == state) {
		sk->sk_user_data = NULL;
		sk->sk_data_ready = state->data_ready;
		sk->sk_write_space = state->write_space;
		sk->sk_state_change = state->state_change;
		sk->sk_error_report = state->error_report;
	}
	write_unlock_bh(&sk->sk_callback_lock);
}

static void terra_detach_stream(struct terra_tsi_socket *state)
{
	if (!state->stream)
		return;
	terra_restore_stream_callbacks(state);
	sock_release(state->stream);
	state->stream = NULL;
}

static void terra_finish_opening(struct terra_tsi_socket *state, int error)
{
	state->connect_error = error;
	smp_store_release(&state->connected, !error);
	WRITE_ONCE(state->sk->sk_state, error ? TCP_CLOSE : TCP_ESTABLISHED);
	state->socket->state = error ? SS_UNCONNECTED : SS_CONNECTED;
	smp_store_release(&state->connecting, false);
	if (error)
		terra_socket_error(state, error);
	else
		terra_socket_wake(state);
}

static int terra_validate_opened(struct terra_tsi_socket *state)
{
	const u8 *frame = state->opened;
	struct sockaddr_in6 peer;
	u16 status;

	if (get_unaligned_le16(frame) != TERRA_OP_TCP_OPENED || get_unaligned_le16(frame + 2) ||
	    get_unaligned_le16(frame + 10))
		return -EPROTO;
	status = get_unaligned_le16(frame + 8);
	if (status)
		return state->opened_needed == 12 ? terra_decode_error(status) : -EPROTO;
	if (state->opened_needed != 32)
		return -EPROTO;
	return terra_decode_peer(&peer, frame + 12);
}

/* Any carrier failure before the opening result means the network is down, not a peer reset. */
static void terra_setup_stream(struct work_struct *work)
{
	struct terra_tsi_socket *state = container_of(work, struct terra_tsi_socket, setup_work);
	struct msghdr message = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
	struct kvec vector;
	int result;

	mutex_lock(&state->select_mutex);
	if (READ_ONCE(state->closing) || !READ_ONCE(state->connecting) || !state->stream)
		goto unlock;
	if (READ_ONCE(state->stream->sk->sk_err)) {
		result = -ENETDOWN;
		goto failed;
	}
	if (READ_ONCE(state->stream->sk->sk_state) != TCP_ESTABLISHED) {
		if (READ_ONCE(state->stream->sk->sk_state) != TCP_SYN_SENT) {
			result = -ENETDOWN;
			goto failed;
		}
		goto unlock;
	}
	state->stream->state = SS_CONNECTED;
	if (state->opening_offset < TERRA_TCP_OPEN_BYTES) {
		vector.iov_base = state->opening + state->opening_offset;
		vector.iov_len = TERRA_TCP_OPEN_BYTES - state->opening_offset;
		result = kernel_sendmsg(state->stream, &message, &vector, 1, vector.iov_len);
		if (result == -EAGAIN)
			goto unlock;
		if (result <= 0) {
			result = -ENETDOWN;
			goto failed;
		}
		state->opening_offset += result;
		if (state->opening_offset < TERRA_TCP_OPEN_BYTES) {
			queue_work(system_unbound_wq, &state->setup_work);
			goto unlock;
		}
	}
	vector.iov_base = state->opened + state->opened_length;
	vector.iov_len = state->opened_needed - state->opened_length;
	result = kernel_recvmsg(state->stream, &message, &vector, 1, vector.iov_len, MSG_DONTWAIT);
	if (result == -EAGAIN)
		goto unlock;
	if (result <= 0) {
		result = -ENETDOWN;
		goto failed;
	}
	state->opened_length += result;
	if (state->opened_length == TERRA_HEADER_BYTES) {
		u32 length = get_unaligned_le32(state->opened + 4);

		if (length != 4 && length != 24) {
			result = -EPROTO;
			goto failed;
		}
		state->opened_needed = TERRA_HEADER_BYTES + length;
	}
	if (state->opened_length < state->opened_needed) {
		queue_work(system_unbound_wq, &state->setup_work);
		goto unlock;
	}
	result = terra_validate_opened(state);
	if (result)
		goto failed;
	state->stream->ops->set_peek_off(state->stream->sk, READ_ONCE(state->sk->sk_peek_off));
	cancel_delayed_work(&state->timeout_work);
	terra_finish_opening(state, 0);
	goto unlock;
failed:
	kernel_sock_shutdown(state->stream, SHUT_RDWR);
	terra_finish_opening(state, result);
unlock:
	mutex_unlock(&state->select_mutex);
}

static void terra_open_timeout(struct work_struct *work)
{
	struct terra_tsi_socket *state = container_of(to_delayed_work(work),
		struct terra_tsi_socket, timeout_work);
	unsigned long now;

	mutex_lock(&state->select_mutex);
	now = jiffies;
	if (READ_ONCE(state->connecting) && !READ_ONCE(state->closing)) {
		if (time_before(now, state->opening_deadline)) {
			mod_delayed_work(system_unbound_wq, &state->timeout_work,
					 state->opening_deadline - now);
		} else {
			kernel_sock_shutdown(state->stream, SHUT_RDWR);
			terra_finish_opening(state, -ETIMEDOUT);
		}
	}
	mutex_unlock(&state->select_mutex);
}

/* Stock vsock reports reset as EOF; normal retirement follows FIN in both directions. */
static void terra_track_tcp_close(struct terra_tsi_socket *state, struct sock *sk)
{
	u32 peer = READ_ONCE(vsock_sk(sk)->peer_shutdown);

	if (peer == SHUTDOWN_MASK && xchg(&state->peer_closed, true))
		return;
	if (READ_ONCE(sk->sk_err))
		terra_socket_error(state, READ_ONCE(sk->sk_err));
	else if (peer == SHUTDOWN_MASK && !READ_ONCE(state->sk->sk_err) &&
		 (!READ_ONCE(state->peer_send_closed) ||
		  !(READ_ONCE(sk->sk_shutdown) & SEND_SHUTDOWN)))
		terra_socket_error(state, -ECONNRESET);
	if (peer & SEND_SHUTDOWN)
		WRITE_ONCE(state->peer_send_closed, true);
}

static void terra_resume_udp(struct terra_tsi_socket *state)
{
	struct sock *stream;

	if (!smp_load_acquire(&state->udp_open))
		return;
	stream = state->stream->sk;
	if (vsock_stream_has_data(vsock_sk(stream)) >= TERRA_HEADER_BYTES ||
	    READ_ONCE(stream->sk_err) || READ_ONCE(stream->sk_state) != TCP_ESTABLISHED ||
	    (READ_ONCE(stream->sk_shutdown) & RCV_SHUTDOWN) ||
	    (READ_ONCE(vsock_sk(stream)->peer_shutdown) & SEND_SHUTDOWN))
		queue_work(system_unbound_wq, &state->udp_work);
}

static void terra_stream_callback(struct sock *sk)
{
	struct terra_tsi_socket *state;

	read_lock_bh(&sk->sk_callback_lock);
	state = sk->sk_user_data;
	if (state && !READ_ONCE(state->closing)) {
		if (state->sk->sk_type == SOCK_DGRAM) {
			terra_resume_udp(state);
			wake_up_interruptible_poll(&state->wait, EPOLLOUT | EPOLLWRNORM);
			if (sock_flag(state->sk, SOCK_FASYNC))
				state->sk->sk_write_space(state->sk);
		} else {
			if (READ_ONCE(state->connecting))
				queue_work(system_unbound_wq, &state->setup_work);
			else
				terra_track_tcp_close(state, sk);
			terra_socket_wake(state);
		}
	}
	if (rcu_access_pointer(sk->sk_wq))
		wake_up_interruptible_all(sk_sleep(sk));
	read_unlock_bh(&sk->sk_callback_lock);
}

static int terra_begin_stream(struct terra_tsi_socket *state)
{
	struct sockaddr_vm host = {
		.svm_family = AF_VSOCK, .svm_cid = 2, .svm_port = TERRA_TCP_PORT,
	};
	u8 *frame = state->opening;
	int error;

	terra_detach_stream(state);
	memset(frame, 0, TERRA_TCP_OPEN_BYTES);
	error = terra_encode_peer(frame + 20, &state->peer);
	if (error)
		return error;
	terra_frame_header(frame, TERRA_OP_TCP_OPEN, TERRA_TCP_OPEN_BYTES - TERRA_HEADER_BYTES);
	put_unaligned_le16(TERRA_NETWORK_VERSION, frame + 8);
	put_unaligned_le16(1, frame + 10);
	put_unaligned_le16(sock_flag(state->sk, SOCK_URGINLINE) |
			   sock_flag(state->sk, SOCK_KEEPOPEN) << 1, frame + 12);
	if (sock_flag(state->sk, SOCK_KEEPOPEN)) {
		const struct tcp_sock *tcp = tcp_sk(state->sk);
		int idle = keepalive_time_when(tcp) / HZ, interval = keepalive_intvl_when(tcp) / HZ;

		put_unaligned_le16(clamp(keepalive_probes(tcp), 1, MAX_TCP_KEEPCNT), frame + 14);
		put_unaligned_le16(clamp(idle, 1, MAX_TCP_KEEPIDLE), frame + 16);
		put_unaligned_le16(clamp(interval, 1, MAX_TCP_KEEPINTVL), frame + 18);
	}
	error = terra_create_stream(state, TERRA_TCP_RECEIVE_BYTES);
	if (error)
		return error;
	terra_stream_options(state);
	WRITE_ONCE(state->peer_send_closed, false);
	WRITE_ONCE(state->peer_closed, false);
	state->opening_offset = 0;
	state->opened_length = 0;
	state->opened_needed = TERRA_HEADER_BYTES;
	terra_attach_callbacks(state);
	WRITE_ONCE(state->connecting, true);
	state->socket->state = SS_CONNECTING;
	error = kernel_connect(state->stream, (struct sockaddr *)&host, sizeof(host), O_NONBLOCK);
	if (error && error != -EINPROGRESS) {
		terra_finish_opening(state, -ENETDOWN);
		return -ENETDOWN;
	}
	state->opening_deadline = jiffies + TERRA_OPEN_TIMEOUT;
	mod_delayed_work(system_unbound_wq, &state->timeout_work, TERRA_OPEN_TIMEOUT);
	queue_work(system_unbound_wq, &state->setup_work);
	return 0;
}

static int terra_wait_connected(struct terra_tsi_socket *state, int flags)
{
	long timeout = sock_sndtimeo(state->sk, flags & O_NONBLOCK);
	long waited;

	if (flags & O_NONBLOCK)
		return -EINPROGRESS;
	waited = wait_event_interruptible_timeout(state->wait,
						  !smp_load_acquire(&state->connecting), timeout);
	if (waited <= 0) {
		mutex_lock(&state->select_mutex);
		if (READ_ONCE(state->connecting)) {
			if (state->stream)
				kernel_sock_shutdown(state->stream, SHUT_RDWR);
			terra_finish_opening(state, waited ? sock_intr_errno(timeout) : -ETIMEDOUT);
		}
		mutex_unlock(&state->select_mutex);
	}
	return state->connect_error;
}

/*
 * Like UDP, a frame is admitted while queued and error memory stay under the receive buffer; an
 * empty queue waives the byte cap, so a frame larger than the remaining room cannot stall the
 * carrier.
 */
static bool terra_udp_queue_admits(struct terra_tsi_socket *state, unsigned int truesize)
{
	struct sk_buff *queued;
	unsigned int memory = 0;
	bool admits;

	spin_lock_bh(&state->datagrams.lock);
	skb_queue_walk(&state->datagrams, queued)
		memory += queued->truesize;
	admits = state->datagrams.qlen < TERRA_UDP_QUEUED_DATAGRAMS &&
		memory + atomic_read(&state->sk->sk_rmem_alloc) < READ_ONCE(state->sk->sk_rcvbuf) &&
		(!state->datagrams.qlen || memory + truesize <= TERRA_UDP_QUEUE_BYTES);
	spin_unlock_bh(&state->datagrams.lock);
	return admits;
}

static void terra_udp_failed(struct terra_tsi_socket *state, int error)
{
	if (cmpxchg(&state->udp_failed, 0, error))
		return;
	kernel_sock_shutdown(state->stream, SHUT_RDWR);
	terra_socket_error(state, error);
}

/*
 * Read a datagram frame's payload straight into page fragments, so a 64 KiB run needs no
 * contiguous allocation or bounce copy. Returns false to stop draining: the queue is full or the
 * carrier failed.
 */
static bool terra_receive_udp_datagram(struct terra_tsi_socket *state, u32 length)
{
	struct msghdr message = { .msg_flags = MSG_DONTWAIT };
	unsigned int payload = TERRA_HEADER_BYTES + length - TERRA_UDP_PREFIX_BYTES;
	u8 prefix[TERRA_UDP_PREFIX_BYTES];
	u8 *segment_field = prefix + TERRA_HEADER_BYTES + TERRA_ENDPOINT_BYTES;
	struct kvec vectors[MAX_SKB_FRAGS + 1];
	struct terra_datagram_cb *cb;
	struct sk_buff *datagram;
	unsigned int count = 0, index;
	u16 segment;
	int error;

	if (!terra_udp_queue_admits(state, SKB_TRUESIZE(0) + PAGE_ALIGN(payload)))
		return false;
	datagram = alloc_skb_with_frags(0, payload, PAGE_ALLOC_COSTLY_ORDER, &error,
					GFP_KERNEL | __GFP_NOWARN);
	if (!datagram) {
		/* Skip the frame: the patched vsock stream drops MSG_TRUNC bytes uncopied. */
		vectors[0] = (struct kvec) { NULL, TERRA_HEADER_BYTES + length };
		if (kernel_recvmsg(state->stream, &message, vectors, 1, vectors[0].iov_len,
				   MSG_DONTWAIT | MSG_TRUNC) == vectors[0].iov_len)
			return true;
		terra_udp_failed(state, -EPROTO);
		return false;
	}
	vectors[count++] = (struct kvec) { prefix, sizeof(prefix) };
	for (index = 0; index < skb_shinfo(datagram)->nr_frags; index++) {
		skb_frag_t *fragment = &skb_shinfo(datagram)->frags[index];

		vectors[count++] = (struct kvec) {
			page_address(skb_frag_page(fragment)) + skb_frag_off(fragment),
			skb_frag_size(fragment)
		};
	}
	datagram->len = payload;
	datagram->data_len = payload;
	if (kernel_recvmsg(state->stream, &message, vectors, count, TERRA_HEADER_BYTES + length,
			   MSG_DONTWAIT) != TERRA_HEADER_BYTES + length)
		goto malformed;
	segment = get_unaligned_le16(segment_field);
	if (get_unaligned_le16(segment_field + 2) ||
	    (segment ? segment > TERRA_UDP_DATAGRAM || payload <= segment ||
		       DIV_ROUND_UP(payload, segment) > TERRA_UDP_MAX_SEGMENTS :
		       payload > TERRA_UDP_DATAGRAM))
		goto malformed;
	cb = TERRA_DATAGRAM_CB(datagram);
	if (terra_decode_peer(&cb->peer, prefix + TERRA_HEADER_BYTES) < 0)
		goto malformed;
	cb->segment = segment;
	mutex_lock(&state->select_mutex);
	if (state->connected && !terra_peer_equal(&cb->peer, &state->peer)) {
		mutex_unlock(&state->select_mutex);
		goto drop;
	}
	mutex_unlock(&state->select_mutex);
	if (READ_ONCE(state->sk->sk_shutdown) & RCV_SHUTDOWN)
		goto drop;
	skb_queue_tail(&state->datagrams, datagram);
	state->sk->sk_data_ready(state->sk);
	return true;
malformed:
	terra_udp_failed(state, -EPROTO);
	kfree_skb(datagram);
	return false;
drop:
	kfree_skb(datagram);
	return true;
}

/* Takes one whole frame off the carrier; an error, close, or malformed frame retires the socket. */
static bool terra_receive_udp_frame(struct terra_tsi_socket *state)
{
	struct sock *transport = state->stream->sk;
	struct msghdr message = { .msg_flags = MSG_DONTWAIT };
	u8 frame[TERRA_HEADER_BYTES + 4 + TERRA_ENDPOINT_BYTES];
	struct kvec vector = { frame, TERRA_HEADER_BYTES };
	struct sockaddr_in6 peer;
	bool is_valid;
	s64 available;
	u32 length;
	u16 opcode, status;

	available = vsock_stream_has_data(vsock_sk(transport));
	if (available < TERRA_HEADER_BYTES)
		goto incomplete;
	if (kernel_recvmsg(state->stream, &message, &vector, 1, TERRA_HEADER_BYTES,
			   MSG_DONTWAIT | MSG_PEEK) != TERRA_HEADER_BYTES) {
		terra_udp_failed(state, -EPROTO);
		return false;
	}
	opcode = get_unaligned_le16(frame);
	length = get_unaligned_le32(frame + 4);
	switch (opcode) {
	case TERRA_OP_UDP_DATAGRAM:
		is_valid = length >= TERRA_UDP_PREFIX_BYTES - TERRA_HEADER_BYTES &&
			   length <= TERRA_UDP_CARRIER_BYTES - TERRA_HEADER_BYTES;
		break;
	case TERRA_OP_UDP_ERROR:
		is_valid = length == 4 + TERRA_ENDPOINT_BYTES;
		break;
	default:
		is_valid = false;
		break;
	}
	if (!is_valid || get_unaligned_le16(frame + 2)) {
		terra_udp_failed(state, -EPROTO);
		return false;
	}
	if (available < TERRA_HEADER_BYTES + length)
		goto incomplete;
	if (opcode != TERRA_OP_UDP_ERROR)
		return terra_receive_udp_datagram(state, length);
	vector.iov_len = sizeof(frame);
	if (kernel_recvmsg(state->stream, &message, &vector, 1, sizeof(frame), MSG_DONTWAIT) !=
	    sizeof(frame)) {
		terra_udp_failed(state, -EPROTO);
		return false;
	}
	status = get_unaligned_le16(frame + 8);
	if (!status || status >= ARRAY_SIZE(terra_errors) || get_unaligned_le16(frame + 10) ||
	    terra_decode_peer(&peer, frame + 12) < 0) {
		terra_udp_failed(state, -EPROTO);
		return false;
	}
	terra_queue_datagram_error(state, terra_decode_error(status), &peer);
	terra_socket_error(state, terra_decode_error(status));
	return true;
incomplete:
	if (READ_ONCE(transport->sk_err) || READ_ONCE(transport->sk_state) != TCP_ESTABLISHED ||
	    (READ_ONCE(transport->sk_shutdown) & RCV_SHUTDOWN) ||
	    (READ_ONCE(vsock_sk(transport)->peer_shutdown) & SEND_SHUTDOWN))
		terra_udp_failed(state, available > 0 ? -EPROTO : -ENETDOWN);
	return false;
}

static void terra_drain_udp(struct work_struct *work)
{
	struct terra_tsi_socket *state = container_of(work, struct terra_tsi_socket, udp_work);
	unsigned int budget;

	if (READ_ONCE(state->closing) || !smp_load_acquire(&state->udp_open) ||
	    READ_ONCE(state->udp_failed))
		return;
	for (budget = 0; budget < TERRA_DRAIN_BUDGET; budget++)
		if (!terra_receive_udp_frame(state))
			return;
	queue_work(system_unbound_wq, &state->udp_work);
}

/* Open the socket's UDP carrier once, synchronously, before any datagram frame is accepted. */
static int terra_udp_open(struct terra_tsi_socket *state)
{
	struct sockaddr_vm host = {
		.svm_family = AF_VSOCK, .svm_cid = 2, .svm_port = TERRA_UDP_PORT,
	};
	struct msghdr message = { .msg_flags = MSG_NOSIGNAL };
	u8 frame[12] = {};
	struct kvec vector = { frame, sizeof(frame) };
	u16 status;
	int error;

	if (state->udp_open)
		return READ_ONCE(state->udp_failed);
	if (!state->udp_frame) {
		state->udp_frame = kmalloc(TERRA_UDP_FRAME_BYTES, GFP_KERNEL);
		if (!state->udp_frame)
			return -ENOMEM;
	}
	error = terra_create_stream(state, TERRA_UDP_CARRIER_BYTES);
	if (error)
		return error;
	WRITE_ONCE(state->stream->sk->sk_sndtimeo, TERRA_OPEN_TIMEOUT);
	WRITE_ONCE(state->stream->sk->sk_rcvtimeo, TERRA_OPEN_TIMEOUT);
	error = -ENETDOWN;
	if (kernel_connect(state->stream, (struct sockaddr *)&host, sizeof(host), 0))
		goto release;
	terra_frame_header(frame, TERRA_OP_UDP_OPEN, 4);
	put_unaligned_le16(TERRA_NETWORK_VERSION, frame + 8);
	if (kernel_sendmsg(state->stream, &message, &vector, 1, sizeof(frame)) != sizeof(frame))
		goto release;
	if (kernel_recvmsg(state->stream, &message, &vector, 1, sizeof(frame), MSG_WAITALL) !=
	    sizeof(frame))
		goto release;
	error = -EPROTO;
	if (get_unaligned_le16(frame) != TERRA_OP_UDP_OPENED || get_unaligned_le16(frame + 2) ||
	    get_unaligned_le32(frame + 4) != 4 || get_unaligned_le16(frame + 10))
		goto release;
	status = get_unaligned_le16(frame + 8);
	if (status) {
		error = terra_decode_error(status);
		goto release;
	}
	terra_attach_callbacks(state);
	smp_store_release(&state->udp_open, true);
	queue_work(system_unbound_wq, &state->udp_work);
	return 0;
release:
	sock_release(state->stream);
	state->stream = NULL;
	return error;
}

static bool terra_udp_writable(struct terra_tsi_socket *state, unsigned int length)
{
	struct sock *transport = state->stream->sk;

	return READ_ONCE(state->udp_failed) || READ_ONCE(state->sk->sk_err) ||
		(READ_ONCE(state->sk->sk_shutdown) & SEND_SHUTDOWN) ||
		READ_ONCE(transport->sk_err) || READ_ONCE(transport->sk_state) != TCP_ESTABLISHED ||
		vsock_stream_has_space(vsock_sk(transport)) >= length;
}

static int terra_udp_control(struct sock *sk, struct msghdr *message, u16 *segment)
{
	struct cmsghdr *control;

	*segment = READ_ONCE(udp_sk(sk)->gso_size);
	if (message->msg_controllen && !CMSG_FIRSTHDR(message))
		return -EINVAL;
	for_each_cmsghdr(control, message) {
		int value;

		if (!CMSG_OK(message, control))
			return -EINVAL;
		if (control->cmsg_level == SOL_UDP && control->cmsg_type == UDP_SEGMENT) {
			if (control->cmsg_len != CMSG_LEN(sizeof(*segment)))
				return -EINVAL;
			memcpy(segment, CMSG_DATA(control), sizeof(*segment));
			if (!*segment || *segment > TERRA_UDP_DATAGRAM)
				return -EINVAL;
		} else if (control->cmsg_level == SOL_IP && control->cmsg_type == IP_TOS) {
			if (control->cmsg_len == CMSG_LEN(sizeof(u8)))
				value = *(u8 *)CMSG_DATA(control);
			else if (control->cmsg_len == CMSG_LEN(sizeof(value)))
				memcpy(&value, CMSG_DATA(control), sizeof(value));
			else
				return -EINVAL;
			if (value < 0 || value > 255)
				return -EINVAL;
		} else if (control->cmsg_level == SOL_IPV6 && control->cmsg_type == IPV6_TCLASS) {
			if (control->cmsg_len != CMSG_LEN(sizeof(value)))
				return -EINVAL;
			memcpy(&value, CMSG_DATA(control), sizeof(value));
			if (value < -1 || value > 255)
				return -EINVAL;
		} else if (control->cmsg_level == SOL_IP && control->cmsg_type == IP_PKTINFO) {
			struct in_pktinfo info;

			if (control->cmsg_len != CMSG_LEN(sizeof(info)))
				return -EINVAL;
			memcpy(&info, CMSG_DATA(control), sizeof(info));
			if (info.ipi_ifindex)
				return -EOPNOTSUPP;
			if (info.ipi_spec_dst.s_addr &&
			    info.ipi_spec_dst.s_addr != READ_ONCE(inet_sk(sk)->inet_rcv_saddr))
				return -EINVAL;
		} else if (control->cmsg_level == SOL_IPV6 && control->cmsg_type == IPV6_PKTINFO) {
			struct in6_pktinfo info;

			if (control->cmsg_len != CMSG_LEN(sizeof(info)) ||
			    sk->sk_family != AF_INET6)
				return -EINVAL;
			memcpy(&info, CMSG_DATA(control), sizeof(info));
			if (info.ipi6_ifindex)
				return -EOPNOTSUPP;
			if (!ipv6_addr_any(&info.ipi6_addr) &&
			    !ipv6_addr_equal(&info.ipi6_addr, &sk->sk_v6_rcv_saddr))
				return -EINVAL;
		} else {
			return -EOPNOTSUPP;
		}
	}
	return 0;
}

static int terra_send_udp(struct terra_tsi_socket *state, const struct sockaddr_in6 *peer,
			  struct msghdr *message, size_t length, u16 segment, bool nonblock)
{
	struct msghdr forwarded = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
	struct virtio_vsock_sock *transport = vsock_sk(state->stream->sk)->trans;
	unsigned int frame_length = TERRA_UDP_PREFIX_BYTES + length;
	long timeout = sock_sndtimeo(state->sk, nonblock);
	u8 endpoint[TERRA_ENDPOINT_BYTES], *frame = state->udp_frame;
	u32 capacity;
	struct kvec vector;
	long waited;
	int error;

	if (!transport)
		return -ENETDOWN;
	spin_lock_bh(&transport->tx_lock);
	capacity = min(READ_ONCE(transport->buf_alloc), transport->peer_buf_alloc);
	spin_unlock_bh(&transport->tx_lock);
	if (frame_length > capacity)
		return -EMSGSIZE;
	error = sock_error(state->sk);
	if (error)
		return error;
	error = terra_encode_peer(endpoint, peer);
	if (error)
		return error;
	if (!terra_udp_writable(state, frame_length)) {
		error = virtio_transport_send_credit_request(vsock_sk(state->stream->sk));
		if (error < 0)
			return error;
		if (!timeout)
			return -EAGAIN;
		waited = wait_event_interruptible_timeout(state->wait,
							  terra_udp_writable(state, frame_length),
							  timeout);
		if (waited <= 0)
			return waited ? sock_intr_errno(timeout) : -EAGAIN;
	}
	error = sock_error(state->sk);
	if (error)
		return error;
	if (READ_ONCE(state->sk->sk_shutdown) & SEND_SHUTDOWN)
		return -EPIPE;
	if (READ_ONCE(state->udp_failed) || READ_ONCE(state->stream->sk->sk_err) ||
	    READ_ONCE(state->stream->sk->sk_state) != TCP_ESTABLISHED)
		return -ENETDOWN;
	if (frame_length > TERRA_UDP_FRAME_BYTES) {
		frame = kvmalloc(frame_length, GFP_KERNEL);
		if (!frame)
			return -ENOMEM;
	}
	terra_frame_header(frame, TERRA_OP_UDP_SEND, frame_length - TERRA_HEADER_BYTES);
	memcpy(frame + TERRA_HEADER_BYTES, endpoint, sizeof(endpoint));
	/* A GSO send that fits one datagram goes out as one: a run always holds several. */
	put_unaligned_le16(length > segment ? segment : 0,
			   frame + TERRA_HEADER_BYTES + TERRA_ENDPOINT_BYTES);
	put_unaligned_le16(0, frame + TERRA_HEADER_BYTES + TERRA_ENDPOINT_BYTES + 2);
	if (!copy_from_iter_full(frame + TERRA_UDP_PREFIX_BYTES, length, &message->msg_iter)) {
		error = -EFAULT;
		goto free;
	}
	vector.iov_base = frame;
	vector.iov_len = frame_length;
	error = kernel_sendmsg(state->stream, &forwarded, &vector, 1, frame_length);
	if (error == frame_length) {
		error = length;
	} else {
		terra_udp_failed(state, -ENETDOWN);
		error = -ENETDOWN;
	}
free:
	if (frame != state->udp_frame)
		kvfree(frame);
	return error;
}

static void terra_set_udp_peer(struct terra_tsi_socket *state)
{
	const struct sockaddr_in6 *peer = &state->peer;
	struct sock *sk = state->sk;

	lock_sock(sk);
	WRITE_ONCE(inet_sk(sk)->inet_daddr, ipv6_addr_v4mapped(&peer->sin6_addr) ?
		   peer->sin6_addr.s6_addr32[3] : 0);
	inet_sk(sk)->inet_dport = peer->sin6_port;
	if (sk->sk_family == AF_INET6)
		sk->sk_v6_daddr = peer->sin6_addr;
	sk_dst_reset(sk);
	sk->sk_state = TCP_ESTABLISHED;
	if (sk->sk_prot->rehash)
		sk->sk_prot->rehash(sk);
	reuseport_has_conns_set(sk);
	release_sock(sk);
}

static int terra_connect_locked(struct socket *socket, struct sockaddr *peer, int peer_length,
				int flags)
{
	struct terra_tsi_socket *state = terra_socket_state(socket);
	struct sockaddr_in6 target;
	int error, selected;

	if (peer_length < sizeof(peer->sa_family))
		return -EINVAL;
	error = mutex_lock_interruptible(&state->select_mutex);
	if (error)
		return error;
	if (socket->type == SOCK_STREAM && state->mode == TERRA_SOCKET_NATIVE) {
		error = state->native_ops->connect(socket, peer, peer_length, flags);
		goto unlock;
	}
	if (READ_ONCE(state->connecting)) {
		error = -EALREADY;
		goto unlock;
	}
	if (socket->type == SOCK_STREAM && smp_load_acquire(&state->connected)) {
		error = -EISCONN;
		goto unlock;
	}
	selected = terra_tsi_select_native(socket, peer, peer_length);
	if (selected < 0) {
		error = selected;
		goto unlock;
	}
	if (selected) {
		if (socket->type == SOCK_STREAM)
			terra_detach_stream(state);
		error = state->native_ops->connect(socket, peer, peer_length, flags);
		if (!error || (socket->type == SOCK_STREAM && error == -EINPROGRESS)) {
			state->mode = peer->sa_family == AF_UNSPEC ?
				      TERRA_SOCKET_UNSELECTED : TERRA_SOCKET_NATIVE;
			/*
			 * __udp_disconnect keeps sk_v6_daddr, which would keep filtering native
			 * replies to a past external peer.
			 */
			if (socket->type == SOCK_DGRAM && peer->sa_family == AF_UNSPEC &&
			    state->sk->sk_family == AF_INET6) {
				lock_sock(state->sk);
				state->sk->sk_v6_daddr = in6addr_any;
				release_sock(state->sk);
			}
			smp_store_release(&state->connected, false);
		}
		goto unlock;
	}
	error = terra_copy_peer(&target, peer, peer_length);
	if (!error)
		error = terra_bind_external(state);
	if (error)
		goto unlock;
	if (socket->type == SOCK_DGRAM) {
		error = terra_udp_open(state);
		if (error)
			goto unlock;
		state->peer = target;
		state->mode = TERRA_SOCKET_EXTERNAL;
		smp_store_release(&state->connected, true);
		terra_set_udp_peer(state);
		socket->state = SS_CONNECTED;
		goto unlock;
	}
	state->peer = target;
	WRITE_ONCE(state->sk->sk_err, 0);
	state->connect_error = 0;
	state->mode = TERRA_SOCKET_EXTERNAL;
	error = terra_begin_stream(state);
	mutex_unlock(&state->select_mutex);
	return error ?: terra_wait_connected(state, flags);
unlock:
	mutex_unlock(&state->select_mutex);
	return error;
}

/* A nonblocking call fails with -EAGAIN instead of waiting for another call to release `lock`. */
static int terra_lock(struct mutex *lock, bool nonblock)
{
	if (nonblock)
		return mutex_trylock(lock) ? 0 : -EAGAIN;
	return mutex_lock_interruptible(lock);
}

static int terra_connect(struct socket *socket, struct sockaddr *peer, int peer_length, int flags)
{
	struct terra_tsi_socket *state = terra_socket_state(socket);
	int error;

	error = terra_lock(&state->send_mutex, flags & O_NONBLOCK);
	if (error)
		return error;
	error = terra_connect_locked(socket, peer, peer_length, flags);
	mutex_unlock(&state->send_mutex);
	return error;
}

static int terra_listen(struct socket *socket, int backlog)
{
	struct terra_tsi_socket *state = terra_socket_state(socket);
	int error;

	error = mutex_lock_interruptible(&state->select_mutex);
	if (error)
		return error;
	if (state->mode == TERRA_SOCKET_EXTERNAL) {
		error = -EOPNOTSUPP;
	} else {
		error = state->native_ops->listen(socket, backlog);
		if (!error)
			state->mode = TERRA_SOCKET_NATIVE;
	}
	mutex_unlock(&state->select_mutex);
	return error;
}

static int terra_accept(struct socket *socket, struct socket *accepted,
			struct proto_accept_arg *argument)
{
	struct terra_tsi_socket *state = terra_socket_state(socket);
	int error;

	accepted->ops = state->native_ops;
	error = state->native_ops->accept(socket, accepted, argument);
	return error ?: terra_tsi_attach(accepted);
}

static int terra_getname(struct socket *socket, struct sockaddr *peer, int remote)
{
	struct terra_tsi_socket *state = terra_socket_state(socket);
	int length;

	mutex_lock(&state->select_mutex);
	if (!remote || state->mode != TERRA_SOCKET_EXTERNAL)
		length = state->native_ops->getname(socket, peer, remote);
	else if (!smp_load_acquire(&state->connected))
		length = -ENOTCONN;
	else
		length = terra_report_peer(state->sk, &state->peer, peer);
	mutex_unlock(&state->select_mutex);
	return length;
}

static __poll_t terra_socket_poll(struct file *file, struct socket *socket, poll_table *wait)
{
	struct terra_tsi_socket *state = terra_socket_state(socket);
	__poll_t mask = 0;

	if (state->mode != TERRA_SOCKET_EXTERNAL || socket->type == SOCK_DGRAM)
		mask = state->native_ops->poll(file, socket, wait);
	if (socket->type == SOCK_STREAM) {
		if (state->mode != TERRA_SOCKET_EXTERNAL || !state->stream)
			return mask;
		sock_poll_wait(file, socket, wait);
		if (READ_ONCE(state->sk->sk_err))
			mask |= EPOLLERR | EPOLLOUT | EPOLLWRNORM;
		if (READ_ONCE(state->peer_closed))
			mask |= EPOLLHUP;
		if (!smp_load_acquire(&state->connecting) && smp_load_acquire(&state->connected))
			mask |= state->stream->ops->poll(file, state->stream, wait);
		return mask;
	}
	poll_wait(file, &state->wait, wait);
	if (!smp_load_acquire(&state->udp_open))
		return mask;
	sock_poll_wait(file, socket, wait);
	if (READ_ONCE(state->udp_failed))
		return mask | EPOLLERR | EPOLLHUP;
	if (READ_ONCE(state->sk->sk_err))
		mask |= EPOLLERR;
	if (!skb_queue_empty(&state->datagrams))
		mask |= EPOLLIN | EPOLLRDNORM;
	if (!terra_udp_writable(state, TERRA_UDP_FRAME_BYTES))
		mask &= ~(EPOLLOUT | EPOLLWRNORM);
	return mask;
}

static int terra_send_stream(struct terra_tsi_socket *state, struct socket *socket,
			     struct msghdr *message, size_t length)
{
	struct msghdr forwarded = *message;
	int error;

	if (state->mode != TERRA_SOCKET_EXTERNAL)
		return state->native_ops->sendmsg(socket, message, length);
	if (!smp_load_acquire(&state->connected))
		return READ_ONCE(state->connecting) ? -EAGAIN : -ENOTCONN;
	if (message->msg_controllen)
		return -EOPNOTSUPP;
	error = sock_error(state->sk);
	if (error)
		return error;
	forwarded.msg_name = NULL;
	forwarded.msg_namelen = 0;
	error = state->stream->ops->sendmsg(state->stream, &forwarded, length);
	message->msg_iter = forwarded.msg_iter;
	if (error > 0) {
		lock_sock(state->sk);
		tcp_sk(state->sk)->bytes_sent += error;
		release_sock(state->sk);
	}
	return error;
}

/* Reads one send's GSO segment size into `segment` and checks `length` against the GSO limits. */
static int terra_udp_send_segment(struct sock *sk, struct msghdr *message, size_t length,
				  u16 *segment)
{
	int error = terra_udp_control(sk, message, segment);

	if (error)
		return error;
	if (*segment && (*segment > TERRA_UDP_DATAGRAM ||
			 length > (size_t)*segment * TERRA_UDP_MAX_SEGMENTS))
		return -EINVAL;
	if (!*segment && length > TERRA_UDP_DATAGRAM)
		return -EMSGSIZE;
	return 0;
}

static int terra_sendmsg(struct socket *socket, struct msghdr *message, size_t length)
{
	struct terra_tsi_socket *state = terra_socket_state(socket);
	bool nonblock = message->msg_flags & MSG_DONTWAIT;
	struct sockaddr *address = message->msg_name;
	int address_length = message->msg_namelen;
	struct sockaddr_storage connected;
	struct sockaddr_in6 peer;
	int selected, error;
	u16 segment;

	if (socket->type == SOCK_STREAM)
		return terra_send_stream(state, socket, message, length);
	if (state->stream && READ_ONCE(state->sk->sk_shutdown) & SEND_SHUTDOWN)
		return -EPIPE;
	if (address) {
		error = terra_copy_peer(&peer, address, address_length);
		if (error)
			return error;
	} else {
		bool is_connected;

		/* connect rewrites the peer under select_mutex; an unlocked copy could tear it. */
		mutex_lock(&state->select_mutex);
		is_connected = state->connected;
		peer = state->peer;
		mutex_unlock(&state->select_mutex);
		if (!is_connected)
			return state->native_ops->sendmsg(socket, message, length);
		address = (struct sockaddr *)&connected;
		address_length = terra_report_peer(state->sk, &peer, &connected);
	}
	selected = terra_tsi_select_native(socket, address, address_length);
	if (selected)
		return selected < 0 ? selected :
		       state->native_ops->sendmsg(socket, message, length);
	error = terra_udp_send_segment(state->sk, message, length, &segment);
	if (error)
		return error;
	if (READ_ONCE(state->sk->sk_shutdown) & SEND_SHUTDOWN)
		return -EPIPE;
	if (message->msg_flags & ~(MSG_DONTWAIT | MSG_NOSIGNAL))
		return -EOPNOTSUPP;
	error = terra_lock(&state->send_mutex, nonblock);
	if (error)
		return error;
	mutex_lock(&state->select_mutex);
	error = terra_bind_external(state);
	if (!error)
		error = terra_udp_open(state);
	mutex_unlock(&state->select_mutex);
	if (!error)
		error = terra_send_udp(state, &peer, message, length, segment, nonblock);
	mutex_unlock(&state->send_mutex);
	return error;
}

/* Drop `count` delivered bytes from the head skb, unlinking it once nothing is left. */
static void terra_consume_datagram(struct terra_tsi_socket *state, struct sk_buff *datagram,
				   unsigned int count)
{
	if (count < terra_datagram_bytes(datagram)) {
		TERRA_DATAGRAM_CB(datagram)->offset += count;
	} else {
		spin_lock_bh(&state->datagrams.lock);
		__skb_unlink(datagram, &state->datagrams);
		spin_unlock_bh(&state->datagrams.lock);
		kfree_skb(datagram);
	}
	terra_resume_udp(state);
}

/*
 * Append the queued datagrams UDP GRO would merge after `segments` full `segment`-byte datagrams
 * from `peer`: same peer and size, ending at most one shorter. Returns the bytes appended or a
 * negative error.
 */
static int terra_receive_coalesced(struct terra_tsi_socket *state, const struct sockaddr_in6 *peer,
				   unsigned int segment, unsigned int segments,
				   struct msghdr *message, size_t room)
{
	unsigned int bytes, next_segment;
	struct sk_buff *next;
	int appended = 0;
	bool accepted;

	room = min_t(size_t, room, U16_MAX - segment * segments);
	while (segments < TERRA_UDP_MAX_SEGMENTS) {
		spin_lock_bh(&state->datagrams.lock);
		next = skb_peek(&state->datagrams);
		bytes = next ? terra_datagram_bytes(next) : 0;
		next_segment = next ? terra_datagram_segment(next) : 0;
		accepted = bytes && bytes <= room &&
			   terra_peer_equal(&TERRA_DATAGRAM_CB(next)->peer, peer) &&
			   (next_segment == segment ||
			    (next_segment == bytes && bytes < segment)) &&
			   segments + DIV_ROUND_UP(bytes, segment) <= TERRA_UDP_MAX_SEGMENTS;
		if (accepted)
			__skb_unlink(next, &state->datagrams);
		spin_unlock_bh(&state->datagrams.lock);
		if (!accepted)
			break;
		if (skb_copy_datagram_iter(next, TERRA_DATAGRAM_CB(next)->offset,
					   &message->msg_iter, bytes)) {
			kfree_skb(next);
			return -EFAULT;
		}
		kfree_skb(next);
		appended += bytes;
		room -= bytes;
		segments += DIV_ROUND_UP(bytes, segment);
		if (bytes % segment)
			break;
	}
	if (appended)
		terra_resume_udp(state);
	return appended;
}

static int terra_recv_stream(struct terra_tsi_socket *state, struct socket *socket,
			     struct msghdr *message, size_t length, int flags)
{
	int error;

	if (state->mode != TERRA_SOCKET_EXTERNAL)
		return state->native_ops->recvmsg(socket, message, length, flags);
	if (!smp_load_acquire(&state->connected))
		return READ_ONCE(state->connecting) ? -EAGAIN : -ENOTCONN;
	message->msg_namelen = 0;
	error = state->stream->ops->recvmsg(state->stream, message, length, flags);
	mutex_lock(&state->select_mutex);
	WRITE_ONCE(state->sk->sk_peek_off, READ_ONCE(state->stream->sk->sk_peek_off));
	mutex_unlock(&state->select_mutex);
	return !error && READ_ONCE(state->sk->sk_err) ? sock_error(state->sk) : error;
}

/* Reading the native error queue frees receive memory, so it may let the carrier drain again. */
static int terra_recv_error_queue(struct terra_tsi_socket *state, struct socket *socket,
				  struct msghdr *message, size_t length, int flags)
{
	int error = state->native_ops->recvmsg(socket, message, length, flags);

	terra_resume_udp(state);
	return error;
}

/* Takes a datagram the native socket queued, such as a native peer's reply; -EAGAIN means none. */
static int terra_recv_native_datagram(struct terra_tsi_socket *state, struct socket *socket,
				      struct msghdr *message, size_t length, int flags)
{
	int error;

	if (!(state->native_ops->poll(socket->file, socket, NULL) & EPOLLIN))
		return -EAGAIN;
	error = state->native_ops->recvmsg(socket, message, length, flags | MSG_DONTWAIT);
	terra_resume_udp(state);
	return error;
}

static bool terra_udp_receive_ready(struct terra_tsi_socket *state, struct socket *socket)
{
	return !skb_queue_empty(&state->datagrams) || READ_ONCE(state->sk->sk_err) ||
		READ_ONCE(state->udp_failed) ||
		(READ_ONCE(state->sk->sk_shutdown) & RCV_SHUTDOWN) ||
		(state->native_ops->poll(socket->file, socket, NULL) & EPOLLIN);
}

/*
 * Copy the head datagram into `message`; under UDP GRO, every whole segment that fits plus the runs
 * terra_receive_coalesced merges. Returns what recvmsg returns: the bytes copied, the full length
 * when `flags` has MSG_TRUNC, or a negative error.
 */
static int terra_deliver_datagram(struct terra_tsi_socket *state, struct sk_buff *datagram,
				  struct msghdr *message, size_t length, int flags)
{
	struct terra_datagram_cb *cb = TERRA_DATAGRAM_CB(datagram);
	unsigned int available = terra_datagram_bytes(datagram);
	unsigned int segment = terra_datagram_segment(datagram);
	bool is_gro = !(flags & MSG_PEEK) && segment && length > segment &&
		      udp_test_bit(GRO_ENABLED, state->sk);
	unsigned int delivered = is_gro ? min_t(size_t, available, length / segment * segment) :
				 segment;
	unsigned int copied = min_t(size_t, length, delivered);
	int appended;

	if (skb_copy_datagram_iter(datagram, cb->offset, &message->msg_iter, copied))
		return -EFAULT;
	if (copied < delivered)
		message->msg_flags |= MSG_TRUNC;
	if (!(flags & MSG_PEEK))
		terra_consume_datagram(state, datagram, delivered);
	if (is_gro) {
		if (delivered == available && !(available % segment)) {
			appended = terra_receive_coalesced(state, &cb->peer, segment,
							   available / segment, message,
							   length - copied);
			if (appended < 0)
				return appended;
			copied += appended;
			delivered += appended;
		}
		if (delivered > segment) {
			int size = segment;

			put_cmsg(message, SOL_UDP, UDP_GRO, sizeof(size), &size);
		}
	}
	return flags & MSG_TRUNC ? delivered : copied;
}

static int terra_recvmsg(struct socket *socket, struct msghdr *message, size_t length, int flags)
{
	struct terra_tsi_socket *state = terra_socket_state(socket);
	long timeout = sock_rcvtimeo(state->sk, flags & MSG_DONTWAIT);
	struct sk_buff *datagram = NULL;
	long waited;
	int error;

	if (socket->type == SOCK_STREAM)
		return terra_recv_stream(state, socket, message, length, flags);
	if (!smp_load_acquire(&state->udp_open))
		return state->native_ops->recvmsg(socket, message, length, flags);
	if (flags & MSG_ERRQUEUE)
		return terra_recv_error_queue(state, socket, message, length, flags);
	if (flags & ~(MSG_DONTWAIT | MSG_PEEK | MSG_TRUNC | MSG_CMSG_CLOEXEC | MSG_WAITALL))
		return -EOPNOTSUPP;
	error = terra_lock(&state->receive_mutex, flags & MSG_DONTWAIT);
	if (error)
		return error;
	for (;;) {
		error = sock_error(state->sk);
		if (error)
			goto unlock;
		error = terra_recv_native_datagram(state, socket, message, length, flags);
		if (error != -EAGAIN)
			goto unlock;
		spin_lock_bh(&state->datagrams.lock);
		datagram = skb_peek(&state->datagrams);
		if (datagram)
			skb_get(datagram);
		spin_unlock_bh(&state->datagrams.lock);
		if (datagram)
			break;
		error = READ_ONCE(state->udp_failed);
		if (error)
			goto unlock;
		if (state->sk->sk_shutdown & RCV_SHUTDOWN) {
			error = 0;
			goto unlock;
		}
		if (!timeout) {
			error = -EAGAIN;
			goto unlock;
		}
		waited = wait_event_interruptible_timeout(*sk_sleep(state->sk),
							  terra_udp_receive_ready(state, socket),
							  timeout);
		if (waited <= 0) {
			error = waited ? sock_intr_errno(timeout) : -EAGAIN;
			goto unlock;
		}
		timeout = waited;
	}
	error = terra_deliver_datagram(state, datagram, message, length, flags);
	if (error < 0)
		goto unlock;
	if (message->msg_name)
		message->msg_namelen = terra_report_peer(state->sk,
							 &TERRA_DATAGRAM_CB(datagram)->peer,
							 message->msg_name);
	if (state->sk->sk_family == AF_INET &&
	    inet_cmsg_flags(inet_sk(state->sk)) & IP_CMSG_PKTINFO) {
		struct in_pktinfo packet = {
			.ipi_spec_dst.s_addr = inet_sk(state->sk)->inet_rcv_saddr,
			.ipi_addr.s_addr = inet_sk(state->sk)->inet_rcv_saddr,
		};

		put_cmsg(message, SOL_IP, IP_PKTINFO, sizeof(packet), &packet);
	} else if (state->sk->sk_family == AF_INET6 &&
		   inet6_sk(state->sk)->rxopt.bits.rxinfo) {
		struct in6_pktinfo packet = {
			.ipi6_addr = state->sk->sk_v6_rcv_saddr,
		};

		put_cmsg(message, SOL_IPV6, IPV6_PKTINFO, sizeof(packet), &packet);
	}
unlock:
	kfree_skb(datagram);
	mutex_unlock(&state->receive_mutex);
	return error;
}

static int terra_shutdown(struct socket *socket, int direction)
{
	struct terra_tsi_socket *state = terra_socket_state(socket);

	if (state->mode != TERRA_SOCKET_EXTERNAL)
		return state->native_ops->shutdown(socket, direction);
	if (direction < SHUT_RD || direction > SHUT_RDWR)
		return -EINVAL;
	if (socket->type == SOCK_STREAM)
		return smp_load_acquire(&state->connected) ?
		       kernel_sock_shutdown(state->stream, direction) : -ENOTCONN;
	lock_sock(state->sk);
	/* SHUT_RD/WR/RDWR become RCV_SHUTDOWN/SEND_SHUTDOWN/SHUTDOWN_MASK, as in inet_shutdown. */
	state->sk->sk_shutdown |= direction + 1;
	release_sock(state->sk);
	terra_socket_wake(state);
	return 0;
}

static bool terra_udp_option(int level, int option)
{
	return (level == SOL_IP && (option == IP_RECVERR || option == IP_PKTINFO ||
				    option == IP_TTL || option == IP_MTU_DISCOVER ||
				    option == IP_RECVTOS || option == IP_TOS)) ||
	       (level == SOL_IPV6 && (option == IPV6_RECVERR || option == IPV6_RECVPKTINFO ||
				      option == IPV6_UNICAST_HOPS || option == IPV6_MTU_DISCOVER ||
				      option == IPV6_DONTFRAG || option == IPV6_RECVTCLASS ||
				      option == IPV6_TCLASS)) ||
	       (level == SOL_UDP && (option == UDP_GRO || option == UDP_SEGMENT));
}

/* Copies an accepted option to the carrier; a larger UDP receive budget may resume draining. */
static void terra_apply_option(struct terra_tsi_socket *state, struct socket *socket, int level,
			       int option)
{
	if (socket->type == SOCK_STREAM) {
		mutex_lock(&state->select_mutex);
		if (state->stream)
			terra_stream_options(state);
		mutex_unlock(&state->select_mutex);
	} else if (socket->type == SOCK_DGRAM &&
		   ((level == SOL_SOCKET && option == SO_RCVBUF) ||
		    (level == SOL_IP && option == IP_RECVERR) ||
		    (level == SOL_IPV6 && option == IPV6_RECVERR))) {
		terra_resume_udp(state);
	}
}

static bool terra_keepalive_option(int level, int option)
{
	return (level == SOL_SOCKET && option == SO_KEEPALIVE) ||
		(level == SOL_TCP && (option == TCP_KEEPIDLE || option == TCP_KEEPINTVL ||
		 option == TCP_KEEPCNT));
}

/* Protocol-level options the broker's socket honours, so an external socket may get or set them. */
static bool terra_forwarded_option(int type, int level, int option)
{
	return (type == SOCK_DGRAM && terra_udp_option(level, option)) ||
		(type == SOCK_STREAM && terra_keepalive_option(level, option)) ||
		(level == SOL_TCP && (option == TCP_NODELAY || option == TCP_MAXSEG)) ||
		(level == SOL_IP && option == IP_TTL) ||
		(level == SOL_IPV6 && (option == IPV6_V6ONLY || option == IPV6_UNICAST_HOPS));
}

static int terra_setsockopt(struct socket *socket, int level, int option,
			    sockptr_t value, unsigned int length)
{
	struct terra_tsi_socket *state = terra_socket_state(socket);
	bool supported = false;
	int integer, error;

	if (level == SOL_TCP && option == TCP_ULP)
		return -EOPNOTSUPP;
	/* IPV6_ADDRFORM swaps in inet_stream_ops, so terra_release_socket would leak the state. */
	if (level == SOL_IPV6 && option == IPV6_ADDRFORM)
		return -EOPNOTSUPP;
	if (level == SOL_SOCKET) {
		switch (option) {
		case SO_REUSEADDR: case SO_REUSEPORT: case SO_RCVBUF: case SO_SNDBUF:
		case SO_RCVTIMEO_OLD: case SO_SNDTIMEO_OLD:
		case SO_RCVTIMEO_NEW: case SO_SNDTIMEO_NEW:
		case SO_BINDTODEVICE: case SO_MARK: case SO_OOBINLINE:
			supported = true;
			break;
		case SO_KEEPALIVE: case SO_PEEK_OFF:
			supported = socket->type == SOCK_STREAM;
			break;
		case SO_BROADCAST:
			supported = socket->type == SOCK_DGRAM;
			break;
		case SO_RCVLOWAT:
			supported = length >= sizeof(integer) &&
				    !copy_from_sockptr(&integer, value, sizeof(integer)) &&
				    integer == 1;
			break;
		}
	} else if (level == SOL_TCP && option == TCP_NODELAY) {
		supported = length >= sizeof(integer) &&
			!copy_from_sockptr(&integer, value, sizeof(integer)) && integer;
	} else {
		supported = terra_forwarded_option(socket->type, level, option);
	}
	/*
	 * An unlisted option would not reach the broker's socket; failing keeps a guest from
	 * trusting one that never applies, such as SO_ATTACH_FILTER.
	 */
	if (!supported && !(socket->type == SOCK_STREAM && state->mode == TERRA_SOCKET_NATIVE))
		return -ENOPROTOOPT;
	if (socket->type == SOCK_DGRAM && level == SOL_UDP && option == UDP_SEGMENT) {
		if (length < sizeof(integer))
			return -EINVAL;
		if (copy_from_sockptr(&integer, value, sizeof(integer)))
			return -EFAULT;
		if (integer < 0 || integer > TERRA_UDP_DATAGRAM)
			return -EINVAL;
	}
	/* terra_begin_stream sends these to the broker once; later changes would never reach it. */
	if (socket->type == SOCK_STREAM &&
	    ((state->stream && level == SOL_SOCKET && option == SO_OOBINLINE) ||
	     (state->mode == TERRA_SOCKET_EXTERNAL && terra_keepalive_option(level, option))))
		return -EOPNOTSUPP;
	error = level == SOL_SOCKET ? sock_setsockopt(socket, level, option, value, length) :
		state->native_ops->setsockopt(socket, level, option, value, length);
	if (!error)
		terra_apply_option(state, socket, level, option);
	return error;
}

/* Reports an external socket's TCP_INFO from its carrier, since the native TCP never connected. */
static int terra_get_tcp_info(struct terra_tsi_socket *state, char __user *value,
			      int __user *length)
{
	struct virtio_vsock_sock *transport = NULL;
	struct tcp_info information = {};
	struct tcp_sock *tcp = tcp_sk(state->sk);
	u32 outstanding, capacity;
	int size;

	if (get_user(size, length))
		return -EFAULT;
	if (size < 0)
		return -EINVAL;
	mutex_lock(&state->select_mutex);
	information.tcpi_state = smp_load_acquire(&state->connected) ? TCP_ESTABLISHED : TCP_CLOSE;
	if (state->stream) {
		if (READ_ONCE(state->stream->sk->sk_shutdown) & RCV_SHUTDOWN)
			information.tcpi_state = TCP_CLOSE_WAIT;
		else if (READ_ONCE(state->stream->sk->sk_shutdown) & SEND_SHUTDOWN)
			information.tcpi_state = TCP_FIN_WAIT2;
	}
	information.tcpi_snd_mss = tcp->rx_opt.user_mss ?: TERRA_TCP_SEGMENT_BYTES;
	information.tcpi_rcv_mss = TERRA_TCP_SEGMENT_BYTES;
	information.tcpi_advmss = information.tcpi_snd_mss;
	information.tcpi_rcv_space = TERRA_TCP_RECEIVE_BYTES;
	if (state->stream && smp_load_acquire(&state->connected))
		transport = vsock_sk(state->stream->sk)->trans;
	if (transport) {
		lock_sock(state->sk);
		spin_lock_bh(&transport->tx_lock);
		outstanding = transport->tx_cnt - transport->peer_fwd_cnt;
		capacity = min(READ_ONCE(transport->buf_alloc), transport->peer_buf_alloc);
		information.tcpi_snd_wnd = min_t(u32, TERRA_TCP_SEND_BYTES,
						 capacity - min(capacity, outstanding));
		spin_unlock_bh(&transport->tx_lock);
		tcp->bytes_acked = max_t(u64, tcp->bytes_acked, 1 + tcp->bytes_sent -
					 min_t(u64, tcp->bytes_sent, outstanding));
		information.tcpi_bytes_acked = tcp->bytes_acked;
		release_sock(state->sk);
	}
	mutex_unlock(&state->select_mutex);
	size = min_t(unsigned int, size, sizeof(information));
	if (put_user(size, length) || copy_to_user(value, &information, size))
		return -EFAULT;
	return 0;
}

static int terra_getsockopt(struct socket *socket, int level, int option,
			    char __user *value, int __user *length)
{
	struct terra_tsi_socket *state = terra_socket_state(socket);

	if (socket->type == SOCK_STREAM && state->mode == TERRA_SOCKET_EXTERNAL &&
	    level == SOL_TCP && option == TCP_INFO)
		return terra_get_tcp_info(state, value, length);
	if ((state->mode == TERRA_SOCKET_EXTERNAL ||
	     (socket->type == SOCK_DGRAM && smp_load_acquire(&state->udp_open))) &&
	    !(terra_forwarded_option(socket->type, level, option) ||
	      (level == SOL_IP && (option == IP_RECVERR || option == IP_PKTINFO)) ||
	      (level == SOL_IPV6 && (option == IPV6_RECVERR || option == IPV6_RECVPKTINFO))))
		return -ENOPROTOOPT;
	return state->native_ops->getsockopt(socket, level, option, value, length);
}

static int terra_ioctl_socket(struct socket *socket, unsigned int command, unsigned long argument)
{
	struct terra_tsi_socket *state = terra_socket_state(socket);

	if (state->mode == TERRA_SOCKET_EXTERNAL && socket->type == SOCK_STREAM) {
		int error;

		mutex_lock(&state->select_mutex);
		error = state->stream ?
			state->stream->ops->ioctl(state->stream, command, argument) : -ENOTCONN;
		mutex_unlock(&state->select_mutex);
		return error;
	}
	if (command == SIOCINQ && smp_load_acquire(&state->udp_open) &&
	    !skb_queue_empty(&state->datagrams)) {
		struct sk_buff *datagram;
		int bytes;

		if (state->native_ops->poll(socket->file, socket, NULL) & EPOLLIN)
			return state->native_ops->ioctl(socket, command, argument);
		spin_lock_bh(&state->datagrams.lock);
		datagram = skb_peek(&state->datagrams);
		bytes = datagram ? terra_datagram_segment(datagram) : 0;
		spin_unlock_bh(&state->datagrams.lock);
		return put_user(bytes, (int __user *)argument);
	}
	return state->native_ops->ioctl(socket, command, argument);
}

static ssize_t terra_splice_read(struct socket *socket, loff_t *position,
				 struct pipe_inode_info *pipe, size_t length, unsigned int flags)
{
	struct terra_tsi_socket *state = terra_socket_state(socket);

	if (state->mode != TERRA_SOCKET_EXTERNAL)
		return state->native_ops->splice_read ?
		       state->native_ops->splice_read(socket, position, pipe, length, flags) :
		       -EOPNOTSUPP;
	return copy_splice_read(socket->file, position, pipe, length, flags);
}

static int terra_release_socket(struct socket *socket)
{
	struct terra_tsi_socket *state;
	const struct proto_ops *native;

	if (!socket->sk)
		return 0;
	state = terra_socket_state(socket);
	WRITE_ONCE(state->closing, true);
	terra_restore_stream_callbacks(state);
	cancel_delayed_work_sync(&state->timeout_work);
	cancel_work_sync(&state->setup_work);
	cancel_work_sync(&state->udp_work);
	terra_detach_stream(state);
	skb_queue_purge(&state->datagrams);
	kfree(state->udp_frame);
	/*
	 * An external TCP socket only mirrors ESTABLISHED; closing it natively would send FIN on
	 * uninitialized TCP state.
	 */
	if (socket->type == SOCK_STREAM && state->mode == TERRA_SOCKET_EXTERNAL) {
		lock_sock(state->sk);
		WRITE_ONCE(state->sk->sk_state, TCP_CLOSE);
		release_sock(state->sk);
	}
	native = state->native_ops;
	rcu_assign_sk_user_data(socket->sk, NULL);
	socket->ops = native;
	native->release(socket);
	kfree(state);
	return 0;
}

/* Wraps a TCP or UDP socket over IPv4 or IPv6; every other socket stays native. */
int terra_tsi_attach(struct socket *socket)
{
	struct sock *sk = socket->sk;
	struct terra_tsi_socket *state;

	if (!sk || (sk->sk_family != AF_INET && sk->sk_family != AF_INET6) ||
	    !((socket->type == SOCK_STREAM && sk->sk_protocol == IPPROTO_TCP) ||
	      (socket->type == SOCK_DGRAM && sk->sk_protocol == IPPROTO_UDP)))
		return 0;
	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;
	state->socket = socket;
	state->sk = sk;
	state->native_ops = socket->ops;
	state->operations = *socket->ops;
	state->operations.release = terra_release_socket;
	state->operations.connect = terra_connect;
	state->operations.accept = terra_accept;
	state->operations.getname = terra_getname;
	state->operations.poll = terra_socket_poll;
	state->operations.ioctl = terra_ioctl_socket;
	state->operations.listen = terra_listen;
	state->operations.shutdown = terra_shutdown;
	state->operations.setsockopt = terra_setsockopt;
	state->operations.getsockopt = terra_getsockopt;
	state->operations.sendmsg = terra_sendmsg;
	state->operations.recvmsg = terra_recvmsg;
	state->operations.splice_read = terra_splice_read;
	if (socket->type == SOCK_STREAM)
		state->operations.set_peek_off = terra_set_peek_off;
	mutex_init(&state->select_mutex);
	mutex_init(&state->send_mutex);
	mutex_init(&state->receive_mutex);
	init_waitqueue_head(&state->wait);
	skb_queue_head_init(&state->datagrams);
	INIT_WORK(&state->setup_work, terra_setup_stream);
	INIT_DELAYED_WORK(&state->timeout_work, terra_open_timeout);
	INIT_WORK(&state->udp_work, terra_drain_udp);
	if (socket->type == SOCK_STREAM && socket->sk->sk_state != TCP_CLOSE)
		state->mode = TERRA_SOCKET_NATIVE;
	__rcu_assign_sk_user_data_with_flags(socket->sk, state, SK_USER_DATA_NOCOPY);
	set_bit(SOCK_CUSTOM_SOCKOPT, &socket->flags);
	socket->ops = &state->operations;
	return 0;
}

static ssize_t terra_socket_abi_show(struct kobject *object,
				     struct kobj_attribute *attribute, char *buffer)
{
	return sysfs_emit(buffer, "%u\n", TERRA_SOCKET_VERSION);
}

static struct kobj_attribute terra_socket_abi_attribute = __ATTR_RO(terra_socket_abi);

static int __init terra_socket_abi_init(void)
{
	return sysfs_create_file(kernel_kobj, &terra_socket_abi_attribute.attr);
}
subsys_initcall(terra_socket_abi_init);
