// SPDX-License-Identifier: GPL-2.0-only
#include <linux/errno.h>
#include <linux/net.h>
#include <linux/security.h>
#include <net/fib_rules.h>
#include <net/inet_sock.h>
#include <net/ip.h>
#include <net/ip6_fib.h>
#include <net/ip6_route.h>
#include <net/ip_fib.h>
#include <net/ipv6.h>
#include <net/l3mdev.h>
#include <net/route.h>
#include <net/sock.h>

#include <linux/terra_socket.h>

static int terra_tsi_route4(struct sock *sk, __be32 destination,
			    __be16 port)
{
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	struct fib_result result = {};
	struct flowi4 flow;
	int oif = READ_ONCE(sk->sk_bound_dev_if);
	int error;

	if (ipv4_is_loopback(destination) || !destination)
		return 1;
	if (rcu_access_pointer(inet->inet_opt))
		return 1;
	if (!oif)
		oif = READ_ONCE(inet->uc_index);
	if (ipv4_is_multicast(destination) && !oif)
		oif = READ_ONCE(inet->mc_index);

	flowi4_init_output(&flow, oif, READ_ONCE(sk->sk_mark),
			   ip_sock_rt_tos(sk), ip_sock_rt_scope(sk),
			   sk->sk_protocol, inet_sk_flowi_flags(sk),
			   destination, inet->inet_saddr, port,
			   inet->inet_sport, sk_uid(sk));
	if (IS_ENABLED(CONFIG_IP_ROUTE_MULTIPATH) && !inet->inet_sport)
		flow.flowi4_flags |= FLOWI_FLAG_ANY_SPORT;
	security_sk_classify_flow(sk, flowi4_to_flowi_common(&flow));

	rcu_read_lock();
#ifdef CONFIG_IP_MULTIPLE_TABLES
	{
		struct fib_lookup_arg arg = {
			.result = &result,
			.flags = FIB_LOOKUP_NOREF,
		};

		l3mdev_update_flow(net, flowi4_to_flowi(&flow));
		error = fib_rules_lookup(net->ipv4.rules_ops,
					 flowi4_to_flowi(&flow), 0, &arg);
		/* An explicit unreachable rule also returns ENETUNREACH. */
		if (error == -ESRCH)
			error = -ENETUNREACH;
		else
			error = 0;
	}
#else
	error = fib_lookup(net, &flow, &result, 0);
#endif
	rcu_read_unlock();
	if (error != -ENETUNREACH || result.lookup_matched)
		return 1;

	if (ipv4_is_multicast(destination) || ipv4_is_lbcast(destination) ||
	    oif || (sk->sk_userlocks & SOCK_BINDADDR_LOCK &&
		    inet->inet_rcv_saddr) ||
	    ip_sock_rt_scope(sk) != RT_SCOPE_UNIVERSE)
		return -EOPNOTSUPP;
	return port ? 0 : -EINVAL;
}

static int terra_tsi_route6(struct sock *sk, struct sockaddr_in6 *peer)
{
	struct ipv6_pinfo *info = inet6_sk(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	struct fib6_result result = {};
	struct flowi6 flow = {};
	int address_type = ipv6_addr_type(&peer->sin6_addr);
	int oif = READ_ONCE(sk->sk_bound_dev_if);
	int flags = 0;
	int error;
	bool missing;

	if (ipv6_addr_v4mapped(&peer->sin6_addr)) {
		if (ipv6_only_sock(sk))
			return 1;
		return terra_tsi_route4(sk, peer->sin6_addr.s6_addr32[3],
					peer->sin6_port);
	}
	if (ipv6_addr_loopback(&peer->sin6_addr) ||
	    ipv6_addr_any(&peer->sin6_addr) ||
	    address_type & IPV6_ADDR_LINKLOCAL)
		return 1;
	if (rcu_access_pointer(info->opt))
		return 1;
	if (!oif)
		oif = READ_ONCE(info->sticky_pktinfo.ipi6_ifindex);
	if (!oif)
		oif = address_type & IPV6_ADDR_MULTICAST ?
			READ_ONCE(info->mcast_oif) : READ_ONCE(info->ucast_oif);

	flow.flowi6_iif = LOOPBACK_IFINDEX;
	flow.flowi6_oif = oif;
	flow.flowi6_mark = READ_ONCE(sk->sk_mark);
	flow.flowi6_uid = sk_uid(sk);
	flow.flowi6_proto = sk->sk_protocol;
	flow.daddr = peer->sin6_addr;
	flow.saddr = info->saddr;
	if (!ipv6_addr_any(&info->sticky_pktinfo.ipi6_addr))
		flow.saddr = info->sticky_pktinfo.ipi6_addr;
	flow.fl6_dport = peer->sin6_port;
	flow.fl6_sport = inet->inet_sport;
	flow.flowlabel = ip6_make_flowinfo(info->tclass, info->flow_label);
	if (inet6_test_bit(SNDFLOW, sk))
		flow.flowlabel = peer->sin6_flowinfo & IPV6_FLOWINFO_MASK;
	if (IS_ENABLED(CONFIG_IPV6_ROUTE_MULTIPATH) && !inet->inet_sport)
		flow.flowi6_flags |= FLOWI_FLAG_ANY_SPORT;
	if (!ipv6_addr_any(&flow.saddr))
		flags |= RT6_LOOKUP_F_HAS_SADDR;
	else
		flags |= rt6_srcprefs2flags(READ_ONCE(info->srcprefs));
	if (oif || rt6_need_strict(&flow.daddr))
		flags |= RT6_LOOKUP_F_IFACE;
	security_sk_classify_flow(sk, flowi6_to_flowi_common(&flow));

	rcu_read_lock();
#ifdef CONFIG_IPV6_MULTIPLE_TABLES
	{
		struct fib_lookup_arg arg = {
			.lookup_ptr = fib6_table_lookup,
			.lookup_data = &oif,
			.result = &result,
			.flags = FIB_LOOKUP_NOREF,
		};

		l3mdev_update_flow(net, flowi6_to_flowi(&flow));
		error = fib_rules_lookup(net->ipv6.fib6_rules_ops,
					 flowi6_to_flowi(&flow), flags, &arg);
		missing = error == -ESRCH;
	}
#else
	error = fib6_lookup(net, oif, &flow, &result, flags);
	missing = !error && result.f6i == net->ipv6.fib6_null_entry;
#endif
	rcu_read_unlock();
	if (!missing || result.lookup_matched)
		return 1;

	if (address_type & IPV6_ADDR_MULTICAST || peer->sin6_scope_id ||
	    oif || (sk->sk_userlocks & SOCK_BINDADDR_LOCK &&
		    !ipv6_addr_any(&info->saddr)) ||
	    !ipv6_addr_any(&info->sticky_pktinfo.ipi6_addr) ||
	    ip_sock_rt_scope(sk) != RT_SCOPE_UNIVERSE)
		return -EOPNOTSUPP;
	return peer->sin6_port ? 0 : -EINVAL;
}

int terra_tsi_select_native(struct socket *socket, struct sockaddr *peer,
			    int peer_len)
{
	struct sock *sk;

	if (!socket || !socket->sk || !peer ||
	    peer_len < sizeof(peer->sa_family))
		return -EINVAL;
	sk = socket->sk;
	if (sk->sk_family == AF_UNIX || peer->sa_family == AF_UNSPEC)
		return 1;
	if (sk->sk_family != AF_INET && sk->sk_family != AF_INET6)
		return -EAFNOSUPPORT;

	switch (peer->sa_family) {
	case AF_INET: {
		struct sockaddr_in *address = (struct sockaddr_in *)peer;

		if (peer_len < sizeof(*address))
			return -EINVAL;
		if (sk->sk_family == AF_INET6 &&
		    (ipv6_only_sock(sk) || sk->sk_type == SOCK_STREAM))
			return 1;
		return terra_tsi_route4(sk, address->sin_addr.s_addr,
					address->sin_port);
	}
	case AF_INET6: {
		struct sockaddr_in6 address = {};

		if (peer_len < SIN6_LEN_RFC2133)
			return -EINVAL;
		if (sk->sk_family != AF_INET6)
			return -EAFNOSUPPORT;
		memcpy(&address, peer, min_t(size_t, peer_len, sizeof(address)));
		return terra_tsi_route6(sk, &address);
	}
	default:
		return -EAFNOSUPPORT;
	}
}
