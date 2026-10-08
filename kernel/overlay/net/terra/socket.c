// SPDX-License-Identifier: GPL-2.0-only
#include <linux/build_bug.h>
#include <linux/capability.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/ioctl.h>
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

#define TERRA_NETWORK_VERSION 1
#define TERRA_HEADER_BYTES 8
#define TERRA_ENDPOINT_BYTES 20
#define TERRA_TCP_PORT 6002
#define TERRA_UDP_PORT 6003
#define TERRA_TCP_SEGMENT_BYTES 65535
#define TERRA_TCP_RECEIVE_BYTES 81920
#define TERRA_TCP_SEND_BYTES 49152
static_assert(TERRA_TCP_RECEIVE_BYTES + TERRA_TCP_SEND_BYTES == 131072);
#define TERRA_UDP_DATAGRAM 4096
#define TERRA_UDP_MAX_SEGMENTS 64
#define TERRA_UDP_FRAME_BYTES (TERRA_HEADER_BYTES + TERRA_ENDPOINT_BYTES + TERRA_UDP_DATAGRAM)
#define TERRA_UDP_QUEUE_BYTES 65536
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
	struct mutex select_mutex;
	struct mutex send_mutex;
	struct mutex receive_mutex;
	struct work_struct setup_work;
	struct delayed_work timeout_work;
	struct work_struct udp_work;
	wait_queue_head_t wait;
	struct sockaddr_storage peer;
	unsigned int peer_length;
	enum terra_socket_mode mode;
	bool connecting;
	bool connected;
	bool closing;
	bool bound;
	bool udp_connected;
	bool udp_open;
	bool peer_send_closed;
	bool peer_closed;
	int udp_failed;
	int connect_error;
	u8 opening[64];
	u8 opened[64];
	unsigned int opening_length;
	unsigned int opening_offset;
	unsigned int opened_length;
	unsigned int opened_needed;
	unsigned long opening_deadline;
	void (*data_ready)(struct sock *);
	void (*write_space)(struct sock *);
	void (*state_change)(struct sock *);
	void (*error_report)(struct sock *);
	struct sk_buff_head datagrams;
	u8 *udp_frame;
	u8 *udp_receive;
};

static struct terra_tsi_socket *terra_socket_state(struct socket *socket)
{
	return (void *)((uintptr_t)READ_ONCE(socket->sk->sk_user_data) & SK_USER_DATA_PTRMASK);
}

static int terra_decode_error(u16 error)
{
	switch (error) {
	case 1: return -EACCES;
	case 2: return -EINVAL;
	case 3: return -ENOTCONN;
	case 4: return -ESTALE;
	case 5: return -EPROTOTYPE;
	case 6: return -EAGAIN;
	case 7: return -ENOBUFS;
	case 8: return -EALREADY;
	case 9: return -ECANCELED;
	case 10: return -ECONNREFUSED;
	case 11: return -ECONNRESET;
	case 12: return -ETIMEDOUT;
	case 13: return -EHOSTUNREACH;
	case 14: return -EAGAIN;
	case 15: return -EMSGSIZE;
	case 16: return -EPIPE;
	case 17: return -EIO;
	case 18: return -EOPNOTSUPP;
	case 19: return -ENETDOWN;
	default: return -EPROTO;
	}
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
				       const struct sockaddr_storage *peer)
{
	struct flowi6 flow = {};

	if (state->sk->sk_type != SOCK_DGRAM ||
	    (peer->ss_family != AF_INET && peer->ss_family != AF_INET6))
		return;
	if (error < 0)
		error = -error;
	if (state->sk->sk_family == AF_INET ||
	    (inet_test_bit(RECVERR, state->sk) && !inet6_test_bit(RECVERR6, state->sk) &&
	     (peer->ss_family == AF_INET ||
	      ipv6_addr_v4mapped(&((const struct sockaddr_in6 *)peer)->sin6_addr)))) {
		__be32 address;
		__be16 port;

		if (peer->ss_family == AF_INET) {
			address = ((const struct sockaddr_in *)peer)->sin_addr.s_addr;
			port = ((const struct sockaddr_in *)peer)->sin_port;
		} else {
			address = ((const struct sockaddr_in6 *)peer)->sin6_addr.s6_addr32[3];
			port = ((const struct sockaddr_in6 *)peer)->sin6_port;
		}
		ip_local_error(state->sk, error, address, port, 0);
		return;
	}
	if (peer->ss_family == AF_INET) {
		const struct sockaddr_in *address = (const void *)peer;

		ipv6_addr_set_v4mapped(address->sin_addr.s_addr, &flow.daddr);
		flow.fl6_dport = address->sin_port;
	} else {
		const struct sockaddr_in6 *address = (const void *)peer;

		flow.daddr = address->sin6_addr;
		flow.fl6_dport = address->sin6_port;
	}
	ipv6_local_error(state->sk, error, &flow, 0);
}

static int terra_encode_peer(u8 *endpoint, const struct sockaddr_storage *peer,
			     unsigned int peer_length)
{
	memset(endpoint, 0, TERRA_ENDPOINT_BYTES);
	if (peer->ss_family == AF_INET && peer_length >= sizeof(struct sockaddr_in)) {
		const struct sockaddr_in *address = (const void *)peer;

		if (!address->sin_port)
			return -EINVAL;
		endpoint[0] = 4;
		put_unaligned_le16(ntohs(address->sin_port), endpoint + 2);
		memcpy(endpoint + 4, &address->sin_addr, 4);
		return 0;
	}
	if (peer->ss_family == AF_INET6 && peer_length >= 24) {
		const struct sockaddr_in6 *address = (const void *)peer;

		if (address->sin6_scope_id || address->sin6_flowinfo)
			return -EOPNOTSUPP;
		if (!address->sin6_port)
			return -EINVAL;
		endpoint[0] = 6;
		put_unaligned_le16(ntohs(address->sin6_port), endpoint + 2);
		memcpy(endpoint + 4, &address->sin6_addr, 16);
		return 0;
	}
	return -EAFNOSUPPORT;
}

static int terra_decode_peer(struct sockaddr_storage *peer, const u8 *endpoint)
{
	unsigned int index;

	memset(peer, 0, sizeof(*peer));
	if (endpoint[1])
		return -EPROTO;
	if (endpoint[0] == 4) {
		struct sockaddr_in *address = (void *)peer;

		for (index = 8; index < TERRA_ENDPOINT_BYTES; index++)
			if (endpoint[index])
				return -EPROTO;
		address->sin_family = AF_INET;
		address->sin_port = htons(get_unaligned_le16(endpoint + 2));
		memcpy(&address->sin_addr, endpoint + 4, 4);
		return sizeof(*address);
	}
	if (endpoint[0] == 6) {
		struct sockaddr_in6 *address = (void *)peer;

		address->sin6_family = AF_INET6;
		address->sin6_port = htons(get_unaligned_le16(endpoint + 2));
		memcpy(&address->sin6_addr, endpoint + 4, 16);
		return sizeof(*address);
	}
	return -EPROTO;
}

static void terra_canonical_peer(const struct sockaddr_storage *peer, __be32 *address4,
				 struct in6_addr *address6, __be16 *port)
{
	*address4 = 0;
	memset(address6, 0, sizeof(*address6));
	if (peer->ss_family == AF_INET) {
		*address4 = ((const struct sockaddr_in *)peer)->sin_addr.s_addr;
		*port = ((const struct sockaddr_in *)peer)->sin_port;
		return;
	}
	*port = ((const struct sockaddr_in6 *)peer)->sin6_port;
	if (ipv6_addr_v4mapped(&((const struct sockaddr_in6 *)peer)->sin6_addr))
		*address4 = ((const struct sockaddr_in6 *)peer)->sin6_addr.s6_addr32[3];
	else
		*address6 = ((const struct sockaddr_in6 *)peer)->sin6_addr;
}

static bool terra_peer_equal(const struct sockaddr_storage *first,
			     const struct sockaddr_storage *second)
{
	struct in6_addr first6, second6;
	__be32 first4, second4;
	__be16 first_port, second_port;

	terra_canonical_peer(first, &first4, &first6, &first_port);
	terra_canonical_peer(second, &second4, &second6, &second_port);
	return first_port == second_port && first4 == second4 &&
		ipv6_addr_equal(&first6, &second6);
}

static int terra_report_peer(struct terra_tsi_socket *state,
			      struct sockaddr_storage *peer, int length)
{
	struct sockaddr_in address4;
	struct sockaddr_in6 *address6;

	if (state->sk->sk_family != AF_INET6 || peer->ss_family != AF_INET)
		return length;
	address4 = *(struct sockaddr_in *)peer;
	memset(peer, 0, sizeof(*peer));
	address6 = (struct sockaddr_in6 *)peer;
	address6->sin6_family = AF_INET6;
	address6->sin6_port = address4.sin_port;
	ipv6_addr_set_v4mapped(address4.sin_addr.s_addr, &address6->sin6_addr);
	return sizeof(*address6);
}

static int terra_copy_peer(struct sockaddr_storage *destination,
			   const struct sockaddr *peer, int length)
{
	unsigned int required;

	if (length < sizeof(peer->sa_family))
		return -EINVAL;
	switch (peer->sa_family) {
	case AF_INET: required = sizeof(struct sockaddr_in); break;
	case AF_INET6: required = 24; break;
	default: return -EAFNOSUPPORT;
	}
	if (length < required)
		return -EINVAL;
	memset(destination, 0, sizeof(*destination));
	memcpy(destination, peer, min_t(size_t, length, sizeof(*destination)));
	return peer->sa_family == AF_INET ? sizeof(struct sockaddr_in) :
						 sizeof(struct sockaddr_in6);
}

static bool terra_peer_is_host_service(const struct sockaddr_storage *peer)
{
	static const struct in6_addr gateway6 = {
		.s6_addr = { 0xfd, 0x53, 0x4d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
	};

	if (peer->ss_family == AF_INET)
		return ((const struct sockaddr_in *)peer)->sin_addr.s_addr ==
			htonl(0x64600001);
	if (peer->ss_family == AF_INET6) {
		const struct in6_addr *address = &((const struct sockaddr_in6 *)peer)->sin6_addr;

		return ipv6_addr_equal(address, &gateway6) ||
			(ipv6_addr_v4mapped(address) && address->s6_addr32[3] == htonl(0x64600001));
	}
	return false;
}

static int terra_bind_external(struct terra_tsi_socket *state)
{
	struct sockaddr_storage local = { 0 };

	if (inet_sk(state->sk)->inet_num)
		return 0;
	local.ss_family = state->sk->sk_family;
	return state->native_ops->bind(state->socket, (struct sockaddr *)&local,
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
	WRITE_ONCE(transport->sk_sndbuf, min_t(int, READ_ONCE(state->sk->sk_sndbuf), TERRA_TCP_SEND_BYTES));
	state->stream->ops->setsockopt(state->stream, AF_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE,
		KERNEL_SOCKPTR(&buffer), sizeof(buffer));
}

/* Create the per-socket carrier; its guest port never shadows a fixed agent, control, or publication port. */
static int terra_create_stream(struct terra_tsi_socket *state, u64 receive_bytes)
{
	struct sockaddr_vm local = { .svm_family = AF_VSOCK, .svm_cid = 3, .svm_port = VMADDR_PORT_ANY };
	int error;

	error = sock_create_kern(&init_net, AF_VSOCK, SOCK_STREAM, 0, &state->stream);
	if (error)
		return error;
	error = kernel_bind(state->stream, (struct sockaddr *)&local, sizeof(local));
	if (!error) {
		error = kernel_getsockname(state->stream, (struct sockaddr *)&local);
		if (error >= 0)
			error = local.svm_port >= 6000 && local.svm_port <= 6004 &&
				local.svm_port != TERRA_TCP_PORT && local.svm_port != TERRA_UDP_PORT ?
				-EADDRNOTAVAIL : 0;
	}
	if (!error)
		error = state->stream->ops->setsockopt(state->stream, AF_VSOCK,
			SO_VM_SOCKETS_BUFFER_MAX_SIZE, KERNEL_SOCKPTR(&receive_bytes), sizeof(receive_bytes));
	if (!error)
		error = state->stream->ops->setsockopt(state->stream, AF_VSOCK,
			SO_VM_SOCKETS_BUFFER_SIZE, KERNEL_SOCKPTR(&receive_bytes), sizeof(receive_bytes));
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
	struct sockaddr_storage peer;
	u16 status;

	if (get_unaligned_le16(frame) != TERRA_OP_TCP_OPENED || get_unaligned_le16(frame + 2) ||
	    get_unaligned_le16(frame + 10))
		return -EPROTO;
	status = get_unaligned_le16(frame + 8);
	if (status)
		return state->opened_needed == 12 ? terra_decode_error(status) : -EPROTO;
	if (state->opened_needed != 32)
		return -EPROTO;
	return terra_decode_peer(&peer, frame + 12) < 0 ? -EPROTO : 0;
}

/* Every carrier failure before the opening result means networking is unavailable, not a peer reset. */
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
	if (state->opening_offset < state->opening_length) {
		vector.iov_base = state->opening + state->opening_offset;
		vector.iov_len = state->opening_length - state->opening_offset;
		result = kernel_sendmsg(state->stream, &message, &vector, 1, vector.iov_len);
		if (result == -EAGAIN)
			goto unlock;
		if (result <= 0) {
			result = -ENETDOWN;
			goto failed;
		}
		state->opening_offset += result;
		if (state->opening_offset < state->opening_length) {
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
		if (time_before(now, state->opening_deadline))
			mod_delayed_work(system_unbound_wq, &state->timeout_work,
				state->opening_deadline - now);
		else {
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
	else if (peer == SHUTDOWN_MASK &&
		 (!READ_ONCE(state->peer_send_closed) || !(READ_ONCE(sk->sk_shutdown) & SEND_SHUTDOWN)) &&
		 !READ_ONCE(state->sk->sk_err))
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

static int terra_prepare_external(struct terra_tsi_socket *state)
{
	int error;

	if (state->sk->sk_type == SOCK_DGRAM && !state->udp_frame) {
		state->udp_frame = kmalloc(TERRA_UDP_FRAME_BYTES, GFP_KERNEL);
		state->udp_receive = kmalloc(TERRA_UDP_FRAME_BYTES, GFP_KERNEL);
		if (!state->udp_frame || !state->udp_receive) {
			kfree(state->udp_frame);
			kfree(state->udp_receive);
			state->udp_frame = NULL;
			state->udp_receive = NULL;
			return -ENOMEM;
		}
	}
	if (state->bound)
		return 0;
	error = terra_bind_external(state);
	if (!error)
		state->bound = true;
	return error;
}

static int terra_begin_stream(struct terra_tsi_socket *state)
{
	struct sockaddr_vm peer = { .svm_family = AF_VSOCK, .svm_cid = 2, .svm_port = TERRA_TCP_PORT };
	unsigned int payload;
	int error;

	terra_detach_stream(state);
	error = terra_create_stream(state, TERRA_TCP_RECEIVE_BYTES);
	if (error)
		return error;
	terra_stream_options(state);
	memset(state->opening, 0, sizeof(state->opening));
	put_unaligned_le16(TERRA_NETWORK_VERSION, state->opening + 8);
	put_unaligned_le16(sock_flag(state->sk, SOCK_URGINLINE), state->opening + 12);
	if (terra_peer_is_host_service(&state->peer) &&
	    (state->peer.ss_family == AF_INET ||
	     ipv6_addr_v4mapped(&((struct sockaddr_in6 *)&state->peer)->sin6_addr))) {
		__be16 port = state->peer.ss_family == AF_INET ?
			((struct sockaddr_in *)&state->peer)->sin_port :
			((struct sockaddr_in6 *)&state->peer)->sin6_port;

		put_unaligned_le16(2, state->opening + 10);
		put_unaligned_le16(ntohs(port), state->opening + 16);
		payload = 12;
		error = port ? 0 : -EINVAL;
	} else {
		put_unaligned_le16(1, state->opening + 10);
		payload = 8 + TERRA_ENDPOINT_BYTES;
		error = terra_encode_peer(state->opening + 16, &state->peer, state->peer_length);
	}
	if (error) {
		terra_detach_stream(state);
		return error;
	}
	terra_frame_header(state->opening, TERRA_OP_TCP_OPEN, payload);
	state->opening_length = TERRA_HEADER_BYTES + payload;
	WRITE_ONCE(state->peer_send_closed, false);
	WRITE_ONCE(state->peer_closed, false);
	state->opening_offset = 0;
	state->opened_length = 0;
	state->opened_needed = TERRA_HEADER_BYTES;
	terra_attach_callbacks(state);
	WRITE_ONCE(state->connecting, true);
	state->socket->state = SS_CONNECTING;
	error = kernel_connect(state->stream, (struct sockaddr *)&peer, sizeof(peer), O_NONBLOCK);
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

static bool terra_udp_queue_full(struct terra_tsi_socket *state)
{
	struct sk_buff *queued;
	unsigned int memory = 0;
	bool full;

	spin_lock_bh(&state->datagrams.lock);
	skb_queue_walk(&state->datagrams, queued)
		memory += queued->truesize;
	full = state->datagrams.qlen >= TERRA_UDP_QUEUED_DATAGRAMS ||
		memory + atomic_read(&state->sk->sk_rmem_alloc) >= READ_ONCE(state->sk->sk_rcvbuf) ||
		memory + SKB_TRUESIZE(TERRA_ENDPOINT_BYTES + TERRA_UDP_DATAGRAM) > TERRA_UDP_QUEUE_BYTES;
	spin_unlock_bh(&state->datagrams.lock);
	return full;
}

static void terra_udp_failed(struct terra_tsi_socket *state, int error)
{
	if (cmpxchg(&state->udp_failed, 0, error))
		return;
	kernel_sock_shutdown(state->stream, SHUT_RDWR);
	terra_socket_error(state, error);
}

/* Accept one complete frame from the carrier; a carrier error, close, or malformed frame retires the socket. */
static bool terra_receive_udp_frame(struct terra_tsi_socket *state)
{
	struct sock *transport = state->stream->sk;
	struct msghdr message = { .msg_flags = MSG_DONTWAIT };
	struct sockaddr_storage peer;
	struct sk_buff *datagram;
	struct kvec vector;
	s64 available;
	u32 length;
	u16 opcode;
	int result;

	available = vsock_stream_has_data(vsock_sk(transport));
	if (available < TERRA_HEADER_BYTES)
		goto incomplete;
	vector.iov_base = state->udp_receive;
	vector.iov_len = TERRA_HEADER_BYTES;
	if (kernel_recvmsg(state->stream, &message, &vector, 1, TERRA_HEADER_BYTES,
			   MSG_DONTWAIT | MSG_PEEK) != TERRA_HEADER_BYTES) {
		terra_udp_failed(state, -EPROTO);
		return false;
	}
	opcode = get_unaligned_le16(state->udp_receive);
	length = get_unaligned_le32(state->udp_receive + 4);
	if (get_unaligned_le16(state->udp_receive + 2) ||
	    (opcode == TERRA_OP_UDP_DATAGRAM ?
	     length < TERRA_ENDPOINT_BYTES || length > TERRA_ENDPOINT_BYTES + TERRA_UDP_DATAGRAM :
	     opcode != TERRA_OP_UDP_ERROR || length != 4 + TERRA_ENDPOINT_BYTES)) {
		terra_udp_failed(state, -EPROTO);
		return false;
	}
	if (available < TERRA_HEADER_BYTES + length)
		goto incomplete;
	vector.iov_base = state->udp_receive;
	vector.iov_len = TERRA_HEADER_BYTES + length;
	result = kernel_recvmsg(state->stream, &message, &vector, 1, vector.iov_len, MSG_DONTWAIT);
	if (result != TERRA_HEADER_BYTES + length) {
		terra_udp_failed(state, -EPROTO);
		return false;
	}
	if (opcode == TERRA_OP_UDP_ERROR) {
		u16 status = get_unaligned_le16(state->udp_receive + 8);

		if (!status || status > 20 || get_unaligned_le16(state->udp_receive + 10) ||
		    terra_decode_peer(&peer, state->udp_receive + 12) < 0) {
			terra_udp_failed(state, -EPROTO);
			return false;
		}
		terra_queue_datagram_error(state, terra_decode_error(status), &peer);
		terra_socket_error(state, terra_decode_error(status));
		return true;
	}
	if (terra_decode_peer(&peer, state->udp_receive + TERRA_HEADER_BYTES) < 0) {
		terra_udp_failed(state, -EPROTO);
		return false;
	}
	mutex_lock(&state->select_mutex);
	if (state->udp_connected && !terra_peer_equal(&peer, &state->peer)) {
		mutex_unlock(&state->select_mutex);
		return true;
	}
	mutex_unlock(&state->select_mutex);
	if (READ_ONCE(state->sk->sk_shutdown) & RCV_SHUTDOWN)
		return true;
	datagram = alloc_skb(length, GFP_KERNEL);
	if (!datagram)
		return true;
	skb_put_data(datagram, state->udp_receive + TERRA_HEADER_BYTES, length);
	skb_queue_tail(&state->datagrams, datagram);
	state->sk->sk_data_ready(state->sk);
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
		if (terra_udp_queue_full(state) || !terra_receive_udp_frame(state))
			return;
	queue_work(system_unbound_wq, &state->udp_work);
}

/* Open the socket's UDP carrier once, synchronously, before any datagram frame is accepted. */
static int terra_udp_open(struct terra_tsi_socket *state)
{
	struct sockaddr_vm host = { .svm_family = AF_VSOCK, .svm_cid = 2, .svm_port = TERRA_UDP_PORT };
	struct msghdr message = { .msg_flags = MSG_NOSIGNAL };
	struct kvec vector;
	u8 frame[12];
	u16 status;
	int error;

	if (state->udp_open)
		return READ_ONCE(state->udp_failed);
	error = terra_create_stream(state, TERRA_UDP_QUEUE_BYTES);
	if (error)
		return error;
	WRITE_ONCE(state->stream->sk->sk_sndtimeo, TERRA_OPEN_TIMEOUT);
	WRITE_ONCE(state->stream->sk->sk_rcvtimeo, TERRA_OPEN_TIMEOUT);
	error = -ENETDOWN;
	if (kernel_connect(state->stream, (struct sockaddr *)&host, sizeof(host), 0))
		goto release;
	terra_frame_header(frame, TERRA_OP_UDP_OPEN, 4);
	put_unaligned_le16(TERRA_NETWORK_VERSION, frame + 8);
	put_unaligned_le16(0, frame + 10);
	vector.iov_base = frame;
	vector.iov_len = sizeof(frame);
	if (kernel_sendmsg(state->stream, &message, &vector, 1, sizeof(frame)) != sizeof(frame))
		goto release;
	vector.iov_base = frame;
	vector.iov_len = sizeof(frame);
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
			if (control->cmsg_len == CMSG_LEN(sizeof(u8))) {
				value = *(u8 *)CMSG_DATA(control);
			} else if (control->cmsg_len == CMSG_LEN(sizeof(value))) {
				memcpy(&value, CMSG_DATA(control), sizeof(value));
			} else {
				return -EINVAL;
			}
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

			if (control->cmsg_len != CMSG_LEN(sizeof(info)) || sk->sk_family != AF_INET6)
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

static int terra_send_udp(struct terra_tsi_socket *state, struct sockaddr_storage *peer,
			  unsigned int peer_length, struct msghdr *message, size_t length,
			  u16 segment, bool nonblock)
{
	struct msghdr forwarded = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
	struct virtio_vsock_sock *transport = vsock_sk(state->stream->sk)->trans;
	unsigned int count = segment ? max_t(size_t, 1, DIV_ROUND_UP(length, segment)) : 1;
	unsigned int frame_length = length + count * (TERRA_HEADER_BYTES + TERRA_ENDPOINT_BYTES);
	long timeout = sock_sndtimeo(state->sk, nonblock);
	u8 endpoint[TERRA_ENDPOINT_BYTES], *frames = state->udp_frame, *frame;
	size_t remaining = length;
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
	error = terra_encode_peer(endpoint, peer, peer_length);
	if (error)
		return error;
	if (!terra_udp_writable(state, frame_length)) {
		error = virtio_transport_send_credit_request(vsock_sk(state->stream->sk));
		if (error < 0)
			return error;
		if (!timeout)
			return -EAGAIN;
		waited = wait_event_interruptible_timeout(state->wait,
			terra_udp_writable(state, frame_length), timeout);
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
		frames = kmalloc(frame_length, GFP_KERNEL);
		if (!frames)
			return -ENOMEM;
	}
	frame = frames;
	do {
		size_t payload = segment ? min_t(size_t, remaining, segment) : remaining;

		terra_frame_header(frame, TERRA_OP_UDP_SEND, TERRA_ENDPOINT_BYTES + payload);
		memcpy(frame + TERRA_HEADER_BYTES, endpoint, sizeof(endpoint));
		if (!copy_from_iter_full(frame + TERRA_HEADER_BYTES + TERRA_ENDPOINT_BYTES,
					 payload, &message->msg_iter)) {
			error = -EFAULT;
			goto free;
		}
		frame += TERRA_HEADER_BYTES + TERRA_ENDPOINT_BYTES + payload;
		remaining -= payload;
	} while (remaining);
	vector.iov_base = frames;
	vector.iov_len = frame_length;
	error = kernel_sendmsg(state->stream, &forwarded, &vector, 1, frame_length);
	if (error == frame_length) {
		error = length;
	} else {
		terra_udp_failed(state, -ENETDOWN);
		error = -ENETDOWN;
	}
free:
	if (frames != state->udp_frame)
		kfree(frames);
	return error;
}

static void terra_set_udp_peer(struct terra_tsi_socket *state)
{
	struct inet_sock *inet = inet_sk(state->sk);

	lock_sock(state->sk);
	if (state->peer.ss_family == AF_INET) {
		const struct sockaddr_in *peer = (const void *)&state->peer;

		WRITE_ONCE(inet->inet_daddr, peer->sin_addr.s_addr);
		inet->inet_dport = peer->sin_port;
		if (state->sk->sk_family == AF_INET6)
			ipv6_addr_set_v4mapped(peer->sin_addr.s_addr, &state->sk->sk_v6_daddr);
	} else {
		const struct sockaddr_in6 *peer = (const void *)&state->peer;

		state->sk->sk_v6_daddr = peer->sin6_addr;
		inet->inet_dport = peer->sin6_port;
		WRITE_ONCE(inet->inet_daddr, ipv6_addr_v4mapped(&peer->sin6_addr) ?
			peer->sin6_addr.s6_addr32[3] : 0);
	}
	sk_dst_reset(state->sk);
	state->sk->sk_state = TCP_ESTABLISHED;
	if (state->sk->sk_prot->rehash)
		state->sk->sk_prot->rehash(state->sk);
	reuseport_has_conns_set(state->sk);
	release_sock(state->sk);
}

static int terra_connect_locked(struct socket *socket, struct sockaddr *peer, int peer_length, int flags)
{
	struct terra_tsi_socket *state = terra_socket_state(socket);
	struct sockaddr_storage target;
	int error, selected, target_length;

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
			state->mode = peer->sa_family == AF_UNSPEC ? TERRA_SOCKET_UNSELECTED : TERRA_SOCKET_NATIVE;
			/* __udp_disconnect keeps sk_v6_daddr, which would keep filtering native replies to a past external peer. */
			if (socket->type == SOCK_DGRAM && peer->sa_family == AF_UNSPEC &&
			    state->sk->sk_family == AF_INET6) {
				lock_sock(state->sk);
				state->sk->sk_v6_daddr = in6addr_any;
				release_sock(state->sk);
			}
			state->udp_connected = false;
			smp_store_release(&state->connected, false);
		}
		goto unlock;
	}
	target_length = terra_copy_peer(&target, peer, peer_length);
	if (target_length < 0) {
		error = target_length;
		goto unlock;
	}
	error = terra_prepare_external(state);
	if (error)
		goto unlock;
	if (socket->type == SOCK_DGRAM) {
		error = terra_udp_open(state);
		if (error)
			goto unlock;
		state->peer = target;
		state->peer_length = target_length;
		state->mode = TERRA_SOCKET_EXTERNAL;
		state->udp_connected = true;
		smp_store_release(&state->connected, true);
		terra_set_udp_peer(state);
		socket->state = SS_CONNECTED;
		goto unlock;
	}
	state->peer = target;
	state->peer_length = target_length;
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

static int terra_connect(struct socket *socket, struct sockaddr *peer, int peer_length, int flags)
{
	struct terra_tsi_socket *state = terra_socket_state(socket);
	int error;

	if (flags & O_NONBLOCK) {
		if (!mutex_trylock(&state->send_mutex))
			return -EAGAIN;
	} else {
		error = mutex_lock_interruptible(&state->send_mutex);
		if (error)
			return error;
	}
	error = terra_connect_locked(socket, peer, peer_length, flags);
	mutex_unlock(&state->send_mutex);
	return error;
}

static int terra_bind(struct socket *socket, struct sockaddr *peer, int peer_length)
{
	return terra_socket_state(socket)->native_ops->bind(socket, peer, peer_length);
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
	struct sockaddr_storage reported;
	int length;

	mutex_lock(&state->select_mutex);
	if (!remote || state->mode != TERRA_SOCKET_EXTERNAL) {
		mutex_unlock(&state->select_mutex);
		return state->native_ops->getname(socket, peer, remote);
	}
	if (!smp_load_acquire(&state->connected) || (socket->type == SOCK_DGRAM && !state->udp_connected)) {
		mutex_unlock(&state->select_mutex);
		return -ENOTCONN;
	}
	reported = state->peer;
	length = terra_report_peer(state, &reported, state->peer_length);
	memcpy(peer, &reported, length);
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

static int terra_sendmsg(struct socket *socket, struct msghdr *message, size_t length)
{
	struct terra_tsi_socket *state = terra_socket_state(socket);
	struct sockaddr_storage peer;
	int peer_length, selected, error;
	bool nonblock = message->msg_flags & MSG_DONTWAIT;
	u16 segment;

	if (socket->type == SOCK_STREAM) {
		struct msghdr forwarded = *message;

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
	if (state->stream && READ_ONCE(state->sk->sk_shutdown) & SEND_SHUTDOWN)
		return -EPIPE;
	if (message->msg_name) {
		peer_length = terra_copy_peer(&peer, message->msg_name, message->msg_namelen);
		if (peer_length < 0)
			return peer_length;
	} else {
		bool is_connected_externally;

		/* terra_connect rewrites the connected peer under select_mutex; an unlocked copy could mix two peers. */
		mutex_lock(&state->select_mutex);
		is_connected_externally = state->mode == TERRA_SOCKET_EXTERNAL && state->udp_connected;
		if (is_connected_externally) {
			peer = state->peer;
			peer_length = state->peer_length;
		}
		mutex_unlock(&state->select_mutex);
		if (!is_connected_externally)
			return state->native_ops->sendmsg(socket, message, length);
	}
	selected = terra_tsi_select_native(socket, (struct sockaddr *)&peer, peer_length);
	if (selected)
		return selected < 0 ? selected : state->native_ops->sendmsg(socket, message, length);
	error = terra_udp_control(state->sk, message, &segment);
	if (error)
		return error;
	if (segment && (segment > TERRA_UDP_DATAGRAM ||
			length > (size_t)segment * TERRA_UDP_MAX_SEGMENTS))
		return -EINVAL;
	if (!segment && length > TERRA_UDP_DATAGRAM)
		return -EMSGSIZE;
	if (READ_ONCE(state->sk->sk_shutdown) & SEND_SHUTDOWN)
		return -EPIPE;
	if (message->msg_flags & ~(MSG_DONTWAIT | MSG_NOSIGNAL))
		return -EOPNOTSUPP;
	if (nonblock) {
		if (!mutex_trylock(&state->send_mutex))
			return -EAGAIN;
	} else {
		error = mutex_lock_interruptible(&state->send_mutex);
		if (error)
			return error;
	}
	mutex_lock(&state->select_mutex);
	error = terra_prepare_external(state);
	if (!error)
		error = terra_udp_open(state);
	mutex_unlock(&state->select_mutex);
	if (!error)
		error = terra_send_udp(state, &peer, peer_length, message, length, segment, nonblock);
	mutex_unlock(&state->send_mutex);
	return error;
}

static int terra_recvmsg(struct socket *socket, struct msghdr *message, size_t length, int flags)
{
	struct terra_tsi_socket *state = terra_socket_state(socket);
	long timeout = sock_rcvtimeo(state->sk, flags & MSG_DONTWAIT);
	struct sk_buff *datagram = NULL;
	struct sockaddr_storage peer;
	long waited;
	unsigned int copied, available;
	int error, peer_length;

	if (socket->type == SOCK_STREAM) {
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
	if (!smp_load_acquire(&state->udp_open))
		return state->native_ops->recvmsg(socket, message, length, flags);
	if (flags & MSG_ERRQUEUE) {
		error = state->native_ops->recvmsg(socket, message, length, flags);
		terra_resume_udp(state);
		return error;
	}
	if (flags & ~(MSG_DONTWAIT | MSG_PEEK | MSG_TRUNC | MSG_CMSG_CLOEXEC | MSG_WAITALL))
		return -EOPNOTSUPP;
	if (flags & MSG_DONTWAIT) {
		if (!mutex_trylock(&state->receive_mutex))
			return -EAGAIN;
	} else {
		error = mutex_lock_interruptible(&state->receive_mutex);
		if (error)
			return error;
	}
	for (;;) {
		error = sock_error(state->sk);
		if (error)
			goto unlock;
		if (state->native_ops->poll(socket->file, socket, NULL) & EPOLLIN) {
			error = state->native_ops->recvmsg(socket, message, length, flags | MSG_DONTWAIT);
			terra_resume_udp(state);
			if (error != -EAGAIN)
				goto unlock;
		}
		if (flags & MSG_PEEK) {
			spin_lock_bh(&state->datagrams.lock);
			datagram = skb_peek(&state->datagrams);
			if (datagram)
				skb_get(datagram);
			spin_unlock_bh(&state->datagrams.lock);
		} else {
			datagram = skb_dequeue(&state->datagrams);
			if (datagram)
				terra_resume_udp(state);
		}
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
			!skb_queue_empty(&state->datagrams) || READ_ONCE(state->sk->sk_err) ||
			READ_ONCE(state->udp_failed) ||
			(READ_ONCE(state->sk->sk_shutdown) & RCV_SHUTDOWN) ||
			(state->native_ops->poll(socket->file, socket, NULL) & EPOLLIN), timeout);
		if (waited <= 0) {
			error = waited ? sock_intr_errno(timeout) : -EAGAIN;
			goto unlock;
		}
		timeout = waited;
	}
	peer_length = terra_decode_peer(&peer, datagram->data);
	if (peer_length < 0) {
		error = peer_length;
		goto unlock;
	}
	available = datagram->len - TERRA_ENDPOINT_BYTES;
	copied = min_t(size_t, length, available);
	if (copy_to_iter(datagram->data + TERRA_ENDPOINT_BYTES, copied, &message->msg_iter) != copied) {
		error = -EFAULT;
		goto unlock;
	}
	if (copied < available)
		message->msg_flags |= MSG_TRUNC;
	if (message->msg_name) {
		peer_length = terra_report_peer(state, &peer, peer_length);
		memcpy(message->msg_name, &peer, peer_length);
		message->msg_namelen = peer_length;
	}
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
	error = flags & MSG_TRUNC ? available : copied;
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
		return smp_load_acquire(&state->connected) ? kernel_sock_shutdown(state->stream, direction) : -ENOTCONN;
	lock_sock(state->sk);
	state->sk->sk_shutdown |= direction == SHUT_RDWR ? SHUTDOWN_MASK :
		direction == SHUT_RD ? RCV_SHUTDOWN : SEND_SHUTDOWN;
	release_sock(state->sk);
	terra_socket_wake(state);
	return state->udp_connected ? 0 : -ENOTCONN;
}

static bool terra_udp_option(int level, int option)
{
	return (level == SOL_IP && (option == IP_RECVERR || option == IP_PKTINFO ||
		option == IP_TTL || option == IP_MTU_DISCOVER || option == IP_RECVTOS || option == IP_TOS)) ||
		(level == SOL_IPV6 && (option == IPV6_RECVERR || option == IPV6_RECVPKTINFO ||
		option == IPV6_UNICAST_HOPS || option == IPV6_MTU_DISCOVER || option == IPV6_DONTFRAG ||
		option == IPV6_RECVTCLASS || option == IPV6_TCLASS)) ||
		(level == SOL_UDP && (option == UDP_GRO || option == UDP_SEGMENT));
}

static int terra_setsockopt(struct socket *socket, int level, int option,
			    sockptr_t value, unsigned int length)
{
	struct terra_tsi_socket *state = terra_socket_state(socket);
	bool supported = false;
	int integer, error;

	if (level == SOL_TCP && option == TCP_ULP)
		return -EOPNOTSUPP;
	/* IPV6_ADDRFORM replaces sock->ops with inet_stream_ops, so terra_release_socket would never free the attached state. */
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
		case SO_PEEK_OFF:
			supported = socket->type == SOCK_STREAM;
			break;
		case SO_BROADCAST:
			supported = socket->type == SOCK_DGRAM;
			break;
		case SO_RCVLOWAT:
			supported = length >= sizeof(integer) &&
				!copy_from_sockptr(&integer, value, sizeof(integer)) && integer == 1;
			break;
		default:
			break;
		}
	} else if (socket->type == SOCK_DGRAM && terra_udp_option(level, option)) {
		supported = true;
	} else if ((level == SOL_TCP && option == TCP_MAXSEG) ||
		   (level == SOL_IP && option == IP_TTL) ||
		   (level == SOL_IPV6 && option == IPV6_UNICAST_HOPS)) {
		supported = true;
	} else if (level == SOL_TCP && option == TCP_NODELAY) {
		supported = length >= sizeof(integer) &&
			!copy_from_sockptr(&integer, value, sizeof(integer)) && integer;
	} else if (level == SOL_IPV6 && option == IPV6_V6ONLY) {
		supported = true;
	}
	/* An unlisted option would not reach the broker's socket; failing keeps a guest from trusting one that never applies, such as SO_ATTACH_FILTER. */
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
	if (state->stream && socket->type == SOCK_STREAM && level == SOL_SOCKET && option == SO_OOBINLINE)
		return -EOPNOTSUPP;
	error = level == SOL_SOCKET ? sock_setsockopt(socket, level, option, value, length) :
		state->native_ops->setsockopt(socket, level, option, value, length);
	if (!error && socket->type == SOCK_STREAM) {
		mutex_lock(&state->select_mutex);
		if (state->stream)
			terra_stream_options(state);
		mutex_unlock(&state->select_mutex);
	} else if (!error && socket->type == SOCK_DGRAM &&
		   ((level == SOL_SOCKET && option == SO_RCVBUF) ||
		    (level == SOL_IP && option == IP_RECVERR) ||
		    (level == SOL_IPV6 && option == IPV6_RECVERR))) {
		terra_resume_udp(state);
	}
	return error;
}

static int terra_getsockopt(struct socket *socket, int level, int option,
			    char __user *value, int __user *length)
{
	struct terra_tsi_socket *state = terra_socket_state(socket);

	if (socket->type == SOCK_STREAM && state->mode == TERRA_SOCKET_EXTERNAL &&
	    level == SOL_TCP && option == TCP_INFO) {
		struct tcp_info information = {};
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
		information.tcpi_snd_mss = tcp_sk(state->sk)->rx_opt.user_mss ?:
			TERRA_TCP_SEGMENT_BYTES;
		information.tcpi_rcv_mss = TERRA_TCP_SEGMENT_BYTES;
		information.tcpi_advmss = information.tcpi_snd_mss;
		information.tcpi_rcv_space = TERRA_TCP_RECEIVE_BYTES;
		if (state->stream && smp_load_acquire(&state->connected)) {
			struct virtio_vsock_sock *transport = vsock_sk(state->stream->sk)->trans;

			if (transport) {
				struct tcp_sock *tcp = tcp_sk(state->sk);
				u32 outstanding, capacity;

				lock_sock(state->sk);
				spin_lock_bh(&transport->tx_lock);
				outstanding = transport->tx_cnt - transport->peer_fwd_cnt;
				capacity = min(READ_ONCE(transport->buf_alloc), transport->peer_buf_alloc);
				information.tcpi_snd_wnd = min_t(u32, TERRA_TCP_SEND_BYTES,
					capacity - min(capacity, outstanding));
				spin_unlock_bh(&transport->tx_lock);
				tcp->bytes_acked = max_t(u64, tcp->bytes_acked,
					1 + tcp->bytes_sent - min_t(u64, tcp->bytes_sent, outstanding));
				information.tcpi_bytes_acked = tcp->bytes_acked;
				release_sock(state->sk);
			}
		}
		mutex_unlock(&state->select_mutex);
		size = min_t(unsigned int, size, sizeof(information));
		if (put_user(size, length) || copy_to_user(value, &information, size))
			return -EFAULT;
		return 0;
	}

	if ((state->mode == TERRA_SOCKET_EXTERNAL ||
	     (socket->type == SOCK_DGRAM && smp_load_acquire(&state->udp_open))) &&
	    !((socket->type == SOCK_DGRAM && terra_udp_option(level, option)) ||
	      (level == SOL_TCP && (option == TCP_NODELAY || option == TCP_MAXSEG)) ||
	      (level == SOL_IP && (option == IP_TTL || option == IP_RECVERR || option == IP_PKTINFO)) ||
	      (level == SOL_IPV6 && (option == IPV6_V6ONLY || option == IPV6_UNICAST_HOPS ||
		 option == IPV6_RECVERR || option == IPV6_RECVPKTINFO))))
		return -ENOPROTOOPT;
	return state->native_ops->getsockopt(socket, level, option, value, length);
}

static int terra_ioctl_socket(struct socket *socket, unsigned int command, unsigned long argument)
{
	struct terra_tsi_socket *state = terra_socket_state(socket);
	int bytes;

	if (command == _IOR('T', 1, __u16))
		return put_user(TERRA_SOCKET_VERSION, (__u16 __user *)argument);
	if (state->mode == TERRA_SOCKET_EXTERNAL && socket->type == SOCK_STREAM) {
		int error;

		mutex_lock(&state->select_mutex);
		error = state->stream ? state->stream->ops->ioctl(state->stream, command, argument) : -ENOTCONN;
		mutex_unlock(&state->select_mutex);
		return error;
	}
	if (command == SIOCINQ && smp_load_acquire(&state->udp_open) &&
	    !skb_queue_empty(&state->datagrams)) {
		struct sk_buff *datagram;

		if (state->native_ops->poll(socket->file, socket, NULL) & EPOLLIN)
			return state->native_ops->ioctl(socket, command, argument);
		spin_lock_bh(&state->datagrams.lock);
		datagram = skb_peek(&state->datagrams);
		bytes = datagram ? datagram->len - TERRA_ENDPOINT_BYTES : 0;
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
			state->native_ops->splice_read(socket, position, pipe, length, flags) : -EOPNOTSUPP;
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
	kfree(state->udp_receive);
	/* An external TCP socket only mirrors ESTABLISHED; closing it natively would send FIN on uninitialized TCP state. */
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

int terra_tsi_attach(struct socket *socket)
{
	struct terra_tsi_socket *state;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;
	state->socket = socket;
	state->sk = socket->sk;
	state->native_ops = socket->ops;
	state->operations = *socket->ops;
	state->operations.release = terra_release_socket;
	state->operations.bind = terra_bind;
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
