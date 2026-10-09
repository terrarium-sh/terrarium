#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <linux/errqueue.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/if_link.h>
#include <linux/fib_rules.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define PAYLOAD_BYTES (1024 * 1024)
#define WAIT_MS 10000

static void require(int condition, const char *what) {
    if (!condition) {
        fprintf(stderr, "FAIL %s: errno=%d (%s)\n", what, errno, strerror(errno));
        exit(1);
    }
}

static void trace_phase(const char *phase) {
    puts(phase);
    fflush(stdout);
}

static void write_all(int fd, const unsigned char *bytes, size_t length) {
    while (length) {
        ssize_t count = write(fd, bytes, length);
        if (count < 0 && errno == EINTR)
            continue;
        require(count > 0, "blocking write progress");
        bytes += count;
        length -= (size_t)count;
    }
}

static struct sockaddr_in ipv4_address(const char *ip, unsigned short port) {
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(port)};
    require(inet_pton(AF_INET, ip, &address.sin_addr) == 1, "IPv4 address");
    return address;
}

static int create_listener(const struct sockaddr *address, socklen_t length) {
    int fd = socket(address->sa_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(fd >= 0, "create local listener");
    require(bind(fd, address, length) == 0, "bind local listener");
    require(listen(fd, 4) == 0, "listen local service");
    return fd;
}

static unsigned short read_port(int fd) {
    struct sockaddr_in address;
    socklen_t length = sizeof(address);
    require(getsockname(fd, (struct sockaddr *)&address, &length) == 0, "listener address");
    require(length == sizeof(address) && address.sin_family == AF_INET, "listener address shape");
    return ntohs(address.sin_port);
}

static void wait_ready(int epoll_fd, int fd, unsigned int events) {
    struct epoll_event requested = {.events = events | EPOLLRDHUP, .data.fd = fd};
    require(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &requested) == 0, "update epoll interest");
    struct epoll_event ready;
    int count;
    do {
        count = epoll_wait(epoll_fd, &ready, 1, WAIT_MS);
    } while (count < 0 && errno == EINTR);
    require(count == 1 && ready.data.fd == fd, "bounded epoll progress");
}

static void echo_until_fin(int listener, size_t expected_bytes) {
    alarm(30);
    int fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    require(fd >= 0, "accept local connection");
    close(listener);
    unsigned char *bytes = malloc(expected_bytes + 1);
    require(bytes != NULL, "server payload allocation");
    size_t received = 0;
    for (;;) {
        ssize_t count = read(fd, bytes + received, expected_bytes + 1 - received);
        if (count < 0 && errno == EINTR)
            continue;
        require(count >= 0, "server receive");
        if (count == 0)
            break;
        received += (size_t)count;
        require(received <= expected_bytes, "server payload bound");
    }
    require(received == expected_bytes, "all accepted writes precede FIN");
    for (size_t index = 0; index < received; index++)
        require(bytes[index] == (expected_bytes == 8 ? (unsigned char)"01234567"[index] : (unsigned char)(index % 251)), "server payload integrity");
    write_all(fd, bytes, received);
    require(shutdown(fd, SHUT_WR) == 0, "server half close");
    close(fd);
    free(bytes);
    _exit(0);
}

static void exercise_tcp(const struct sockaddr *address, socklen_t length) {
    int original = socket(address->sa_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    require(original >= 0, "nonblocking stream socket");
    int buffer_bytes = 1024;
    require(setsockopt(original, SOL_SOCKET, SO_SNDBUF, &buffer_bytes, sizeof(buffer_bytes)) == 0, "bounded send buffer option");
    int connected = connect(original, address, length);
    require(connected == 0 || (connected < 0 && errno == EINPROGRESS), "nonblocking connect admission");
    int fd = dup(original);
    require(fd >= 0, "duplicate connected descriptor");
    close(original);
    require(fcntl(fd, F_GETFL) & O_NONBLOCK, "duplicate preserves nonblocking state");
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    require(epoll_fd >= 0, "epoll descriptor");
    struct epoll_event event = {.events = EPOLLOUT | EPOLLRDHUP, .data.fd = fd};
    require(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) == 0, "epoll socket registration");
    if (connected != 0)
        wait_ready(epoll_fd, fd, EPOLLOUT);
    int error = -1;
    socklen_t error_length = sizeof(error);
    require(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_length) == 0 && error == 0, "connect completion SO_ERROR");
    struct sockaddr_storage local, peer;
    socklen_t local_length = sizeof(local), peer_length = sizeof(peer);
    require(getsockname(fd, (struct sockaddr *)&local, &local_length) == 0, "connected local address");
    require(getpeername(fd, (struct sockaddr *)&peer, &peer_length) == 0, "connected peer address");
    require(peer.ss_family == address->sa_family, "peer address family");
    unsigned char *bytes = malloc(PAYLOAD_BYTES);
    require(bytes != NULL, "client payload allocation");
    for (size_t index = 0; index < PAYLOAD_BYTES; index++)
        bytes[index] = (unsigned char)(index % 251);
    size_t sent = 0;
    int saw_partial = 0;
    while (sent < PAYLOAD_BYTES) {
        ssize_t count = send(fd, bytes + sent, PAYLOAD_BYTES - sent, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            wait_ready(epoll_fd, fd, EPOLLOUT);
            continue;
        }
        require(count > 0, "nonblocking write progress");
        saw_partial |= (size_t)count < PAYLOAD_BYTES - sent;
        sent += (size_t)count;
    }
    require(saw_partial, "large write exercises partial acceptance");
    require(shutdown(fd, SHUT_WR) == 0, "client half close");
    size_t received = 0;
    unsigned char reply[8192];
    for (;;) {
        ssize_t count = recv(fd, reply, sizeof(reply), 0);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            wait_ready(epoll_fd, fd, EPOLLIN);
            continue;
        }
        require(count >= 0, "reply receive");
        if (count == 0)
            break;
        require(received + (size_t)count <= PAYLOAD_BYTES, "reply byte bound");
        require(memcmp(reply, bytes + received, (size_t)count) == 0, "reply payload integrity");
        received += (size_t)count;
    }
    require(received == PAYLOAD_BYTES, "reply survives client half close");
    free(bytes);
    close(epoll_fd);
    close(fd);
}

static void require_tcp_peek_offset(int fd, int expected) {
    int offset = -2;
    socklen_t length = sizeof(offset);
    require(getsockopt(fd, SOL_SOCKET, SO_PEEK_OFF, &offset, &length) == 0 &&
            length == sizeof(offset) && offset == expected, "TCP peek offset readback");
}

static void exercise_tcp_peek_offset(const struct sockaddr *address, socklen_t length,
                                     int configure_before_connect) {
    int fd = socket(address->sa_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(fd >= 0, "TCP peek offset socket");
    struct timeval timeout = {.tv_sec = 5};
    require(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "TCP peek receive deadline");
    require(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0, "TCP peek send deadline");
    int offset = 0;
    if (configure_before_connect)
        require(setsockopt(fd, SOL_SOCKET, SO_PEEK_OFF, &offset, sizeof(offset)) == 0, "unbound TCP peek offset");
    require(connect(fd, address, length) == 0, "TCP peek offset connect");
    int error = -1;
    socklen_t error_length = sizeof(error);
    require(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_length) == 0 && error == 0, "TCP peek connect SO_ERROR");
    if (!configure_before_connect)
        require(setsockopt(fd, SOL_SOCKET, SO_PEEK_OFF, &offset, sizeof(offset)) == 0, "post-connect TCP peek offset");
    require_tcp_peek_offset(fd, 0);
    write_all(fd, (const unsigned char *)"01234567", 8);
    require(shutdown(fd, SHUT_WR) == 0, "TCP peek client FIN");
    unsigned char byte;
    require(recv(fd, &byte, 1, MSG_PEEK) == 1 && byte == '0', "first TCP offset peek");
    require_tcp_peek_offset(fd, 1);
    require(recv(fd, &byte, 1, MSG_PEEK) == 1 && byte == '1', "second TCP offset peek advances");
    require_tcp_peek_offset(fd, 2);
    require(recv(fd, &byte, 1, 0) == 1 && byte == '0', "TCP receive preserves peeked bytes");
    require_tcp_peek_offset(fd, 1);
    require(recv(fd, &byte, 1, MSG_PEEK) == 1 && byte == '2', "TCP receive adjusts peek offset back");
    require_tcp_peek_offset(fd, 2);
    require(recv(fd, NULL, 1, MSG_TRUNC | MSG_DONTWAIT) == 1, "TCP null-buffer MSG_TRUNC discards accepted data");
    require_tcp_peek_offset(fd, 1);
    require(recv(fd, &byte, 1, MSG_PEEK) == 1 && byte == '3', "TCP discard adjusts peek offset back");
    require_tcp_peek_offset(fd, 2);
    offset = -1;
    require(setsockopt(fd, SOL_SOCKET, SO_PEEK_OFF, &offset, sizeof(offset)) == 0, "disable TCP peek offset");
    require(recv(fd, &byte, 1, MSG_PEEK) == 1 && byte == '2', "traditional TCP peek head");
    require(recv(fd, &byte, 1, MSG_PEEK) == 1 && byte == '2', "traditional TCP peek repeats head");
    require_tcp_peek_offset(fd, -1);
    unsigned char remaining[6];
    size_t received = 0;
    while (received < sizeof(remaining)) {
        ssize_t count = recv(fd, remaining + received, sizeof(remaining) - received, 0);
        if (count < 0 && errno == EINTR)
            continue;
        require(count > 0, "TCP peek remaining receive");
        received += (size_t)count;
    }
    require(memcmp(remaining, "234567", sizeof(remaining)) == 0, "TCP peek and discard preserve remaining payload");
    require(recv(fd, &byte, 1, 0) == 0, "TCP peek peer FIN");
    close(fd);
}

static void exercise_local_stream(struct sockaddr *address, socklen_t length) {
    int listener = create_listener(address, length);
    if (address->sa_family != AF_UNIX) {
        socklen_t bound_length = length;
        require(getsockname(listener, address, &bound_length) == 0 && bound_length == length, "bound local address");
    }
    unsigned int cases = address->sa_family == AF_UNIX ? 1 : 3;
    for (unsigned int index = 0; index < cases; index++) {
        pid_t child = fork();
        require(child >= 0, "fork inherited listener");
        if (child == 0)
            echo_until_fin(listener, index == 0 ? PAYLOAD_BYTES : 8);
        if (index == 0)
            exercise_tcp(address, length);
        else
            exercise_tcp_peek_offset(address, length, index == 2);
        int status;
        require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "inherited listener server status");
    }
    close(listener);
}

static void exercise_concurrent_tcp(struct sockaddr *address, socklen_t length) {
    enum { WRITER_BYTES = 8192 };
    int fd = socket(address->sa_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(fd >= 0 && connect(fd, address, length) == 0, "concurrent TCP connect");
    int start[2];
    require(pipe(start) == 0, "concurrent TCP start pipe");
    pid_t writers[2];
    for (unsigned int writer = 0; writer < 2; writer++) {
        writers[writer] = fork();
        require(writers[writer] >= 0, "concurrent TCP writer fork");
        if (writers[writer] == 0) {
            alarm(20);
            close(start[1]);
            char ready;
            require(read(start[0], &ready, 1) == 1, "concurrent TCP start");
            close(start[0]);
            int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
            require(epoll_fd >= 0, "concurrent TCP writer epoll");
            struct epoll_event event = {.events = EPOLLOUT, .data.fd = fd};
            require(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) == 0, "concurrent TCP writer readiness");
            for (unsigned int index = 0; index < WRITER_BYTES;) {
                unsigned char byte = (unsigned char)((writer << 7) | (index & 127));
                ssize_t sent = send(fd, &byte, 1, MSG_DONTWAIT | MSG_NOSIGNAL);
                if (sent < 0 && errno == EINTR)
                    continue;
                if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    wait_ready(epoll_fd, fd, EPOLLOUT);
                    continue;
                }
                require(sent == 1, "concurrent TCP byte acceptance");
                index++;
            }
            close(epoll_fd);
            close(fd);
            _exit(0);
        }
    }
    close(start[0]);
    require(write(start[1], "GO", 2) == 2, "release concurrent TCP writers");
    close(start[1]);
    for (unsigned int writer = 0; writer < 2; writer++) {
        int status;
        require(waitpid(writers[writer], &status, 0) == writers[writer] && WIFEXITED(status) && WEXITSTATUS(status) == 0, "concurrent TCP writer status");
    }
    require(shutdown(fd, SHUT_WR) == 0, "concurrent TCP FIN after accepted bytes");
    unsigned int received[2] = {0, 0};
    unsigned char bytes[8192];
    ssize_t count;
    while ((count = recv(fd, bytes, sizeof(bytes), 0)) > 0) {
        for (ssize_t index = 0; index < count; index++) {
            unsigned int writer = bytes[index] >> 7;
            require(received[writer] < WRITER_BYTES && (bytes[index] & 127) == (received[writer] & 127), "concurrent TCP preserves each writer's byte order");
            received[writer]++;
        }
    }
    require(count == 0 && received[0] == WRITER_BYTES && received[1] == WRITER_BYTES, "concurrent TCP accepted bytes precede EOF");
    close(fd);
}

static void exercise_refused_local(unsigned short port) {
    struct sockaddr_in address = ipv4_address("127.0.0.2", port);
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    require(fd >= 0, "refused local socket");
    int result = connect(fd, (struct sockaddr *)&address, sizeof(address));
    if (result < 0 && errno == EINPROGRESS) {
        int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        require(epoll_fd >= 0, "refusal epoll descriptor");
        struct epoll_event event = {.events = EPOLLOUT, .data.fd = fd};
        require(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) == 0, "refusal readiness registration");
        wait_ready(epoll_fd, fd, EPOLLOUT);
        int error = 0;
        socklen_t length = sizeof(error);
        require(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == ECONNREFUSED, "local refusal never falls through to host");
        close(epoll_fd);
    } else {
        require(result < 0 && errno == ECONNREFUSED, "immediate local refusal");
    }
    close(fd);
}

/* IPV6_ADDRFORM would swap the TSI socket operations for inet_stream_ops and leak the attached state. */
static void exercise_mapped_addrform(void) {
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(listener >= 0, "IPV6_ADDRFORM listener");
    struct sockaddr_in address = ipv4_address("127.0.0.2", 0);
    require(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0 && listen(listener, 1) == 0, "IPV6_ADDRFORM listen");
    struct sockaddr_in6 mapped = {.sin6_family = AF_INET6, .sin6_port = htons(read_port(listener))};
    require(inet_pton(AF_INET6, "::ffff:127.0.0.2", &mapped.sin6_addr) == 1, "IPV6_ADDRFORM mapped peer");
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(fd >= 0 && connect(fd, (struct sockaddr *)&mapped, sizeof(mapped)) == 0, "IPV6_ADDRFORM native mapped connect");
    int family = PF_INET;
    require(setsockopt(fd, SOL_IPV6, IPV6_ADDRFORM, &family, sizeof(family)) < 0 && errno == EOPNOTSUPP, "IPV6_ADDRFORM refused on a TSI socket");
    close(fd);
    close(listener);
}

static void exercise_local(void) {
    struct sockaddr_in ipv4 = ipv4_address("127.0.0.2", 0);
    exercise_local_stream((struct sockaddr *)&ipv4, sizeof(ipv4));
    struct sockaddr_in6 ipv6 = {.sin6_family = AF_INET6};
    require(inet_pton(AF_INET6, "::1", &ipv6.sin6_addr) == 1, "IPv6 loopback");
    exercise_local_stream((struct sockaddr *)&ipv6, sizeof(ipv6));
    struct sockaddr_in6 mapped = {.sin6_family = AF_INET6};
    require(inet_pton(AF_INET6, "::ffff:127.0.0.2", &mapped.sin6_addr) == 1, "mapped loopback");
    exercise_local_stream((struct sockaddr *)&mapped, sizeof(mapped));
    struct sockaddr_un local = {.sun_family = AF_UNIX};
    snprintf(local.sun_path + 1, sizeof(local.sun_path) - 1, "terra-socket-%ld", (long)getpid());
    socklen_t length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + strlen(local.sun_path + 1));
    exercise_local_stream((struct sockaddr *)&local, length);
    int reservation = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(reservation >= 0, "local refusal reservation");
    ipv4 = ipv4_address("127.0.0.2", 0);
    require(bind(reservation, (struct sockaddr *)&ipv4, sizeof(ipv4)) == 0, "reserve refused local port");
    exercise_refused_local(read_port(reservation));
    close(reservation);
    exercise_mapped_addrform();
    puts("SOCKET_LOCAL_OK");
}

static void require_option(int fd, int level, int option) {
    int enabled = 0;
    socklen_t length = sizeof(enabled);
    require(getsockopt(fd, level, option, &enabled, &length) == 0 && length == sizeof(enabled) && enabled == 1, "enabled UDP option readback");
}

static void consume_udp_denial(int fd) {
    int error = 0;
    for (unsigned int attempt = 0; !error && attempt < WAIT_MS / 10; attempt++) {
        socklen_t error_length = sizeof(error);
        require(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_length) == 0, "consume UDP SO_ERROR");
        if (!error)
            usleep(10000);
    }
    require(error == EACCES, "denied UDP SO_ERROR");
}

static void consume_datagram_error(int fd, const struct sockaddr *peer, socklen_t peer_length) {
    char payload;
    struct iovec bytes = {.iov_base = &payload, .iov_len = sizeof(payload)};
    union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(sizeof(struct sock_extended_err) + sizeof(struct sockaddr_in6))];
    } control;
    struct sockaddr_storage destination;
    struct msghdr message = {
        .msg_name = &destination,
        .msg_namelen = sizeof(destination),
        .msg_iov = &bytes,
        .msg_iovlen = 1,
        .msg_control = control.bytes,
        .msg_controllen = sizeof(control.bytes),
    };
    require(recvmsg(fd, &message, MSG_ERRQUEUE | MSG_DONTWAIT) == 0, "SO_ERROR consumption preserves zero-payload queued local error");
    require((message.msg_flags & MSG_ERRQUEUE) && !(message.msg_flags & MSG_CTRUNC), "complete native error queue control");
    require(message.msg_namelen == peer_length && destination.ss_family == peer->sa_family, "UDP error original destination family");
    if (peer->sa_family == AF_INET) {
        const struct sockaddr_in *expected = (const void *)peer;
        const struct sockaddr_in *actual = (const void *)&destination;
        require(actual->sin_port == expected->sin_port && actual->sin_addr.s_addr == expected->sin_addr.s_addr, "UDP error original IPv4 destination");
    } else {
        const struct sockaddr_in6 *expected = (const void *)peer;
        const struct sockaddr_in6 *actual = (const void *)&destination;
        require(actual->sin6_port == expected->sin6_port && memcmp(&actual->sin6_addr, &expected->sin6_addr, sizeof(actual->sin6_addr)) == 0, "UDP error original IPv6 destination");
    }
    int error_level = peer->sa_family == AF_INET ? SOL_IP : SOL_IPV6;
    int error_option = peer->sa_family == AF_INET ? IP_RECVERR : IPV6_RECVERR;
    struct cmsghdr *entry = CMSG_FIRSTHDR(&message);
    require(entry && entry->cmsg_level == error_level && entry->cmsg_type == error_option && entry->cmsg_len >= CMSG_LEN(sizeof(struct sock_extended_err) + sizeof(struct sockaddr)), "UDP error metadata shape");
    require(message.msg_controllen == CMSG_ALIGN(entry->cmsg_len), "one UDP local error control message");
    const struct sock_extended_err *queued = (const void *)CMSG_DATA(entry);
    require(queued->ee_errno == EACCES && queued->ee_origin == SO_EE_ORIGIN_LOCAL && queued->ee_type == 0 && queued->ee_code == 0 && queued->ee_info == 0 && queued->ee_data == 0, "UDP error uses truthful local metadata");
    require(SO_EE_OFFENDER(queued)->sa_family == AF_UNSPEC, "UDP local error has no invented ICMP offender");
}

static void exercise_datagram_error(const struct sockaddr *peer, socklen_t peer_length, int level, int option) {
    int fd = socket(peer->sa_family, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    require(fd >= 0, "UDP error queue socket");
    int enabled = 1;
    require(setsockopt(fd, level, option, &enabled, sizeof(enabled)) == 0, "enable native UDP error queue");
    require_option(fd, level, option);
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    require(epoll_fd >= 0, "UDP error readiness descriptor");
    struct epoll_event interest = {.events = EPOLLERR, .data.fd = fd};
    require(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &interest) == 0, "register UDP error readiness");
    require(sendto(fd, "E", 1, 0, peer, peer_length) == 1, "denied UDP send accepted asynchronously");
    struct epoll_event ready;
    int count;
    do {
        count = epoll_wait(epoll_fd, &ready, 1, WAIT_MS);
    } while (count < 0 && errno == EINTR);
    require(count == 1 && ready.data.fd == fd && (ready.events & EPOLLERR), "denied UDP becomes error ready");
    consume_udp_denial(fd);
    require_option(fd, level, option);
    consume_datagram_error(fd, peer, peer_length);
    struct msghdr message = {0};
    require(recvmsg(fd, &message, MSG_ERRQUEUE | MSG_DONTWAIT) < 0 && errno == EAGAIN, "UDP error queue drained exactly once");
    close(epoll_fd);
    close(fd);
}

static void exercise_errors(void) {
    struct sockaddr_in ipv4 = ipv4_address("192.0.2.90", 80);
    exercise_datagram_error((struct sockaddr *)&ipv4, sizeof(ipv4), SOL_IP, IP_RECVERR);
    struct sockaddr_in6 ipv6 = {.sin6_family = AF_INET6, .sin6_port = htons(80)};
    require(inet_pton(AF_INET6, "::ffff:192.0.2.90", &ipv6.sin6_addr) == 1, "mapped UDP error destination");
    exercise_datagram_error((struct sockaddr *)&ipv6, sizeof(ipv6), SOL_IP, IP_RECVERR);
    require(inet_pton(AF_INET6, "2001:db8::90", &ipv6.sin6_addr) == 1, "IPv6 UDP error destination");
    exercise_datagram_error((struct sockaddr *)&ipv6, sizeof(ipv6), SOL_IPV6, IPV6_RECVERR);
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(fd >= 0, "blocking denied UDP socket");
    struct timeval timeout = {.tv_sec = 10};
    require(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0, "blocking denied UDP send deadline");
    require(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "blocking denied UDP receive deadline");
    trace_phase("SOCKET_PHASE blocking_denial_send");
    require(sendto(fd, "B", 1, 0, (struct sockaddr *)&ipv4, sizeof(ipv4)) == 1, "blocking UDP send accepts without a host round trip");
    unsigned short bound_port = read_port(fd);
    require(bound_port != 0, "external UDP opening assigns a native local port");
    char denial;
    require(recv(fd, &denial, 1, 0) < 0 && errno == EACCES, "blocking UDP denial arrives as the asynchronous socket error");
    trace_phase("SOCKET_PHASE blocking_denial_returned");
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    require(epoll_fd >= 0, "UDP pending send error readiness descriptor");
    struct epoll_event ready = {.events = EPOLLERR, .data.fd = fd};
    require(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ready) == 0, "register UDP pending send error readiness");
    require(sendto(fd, "S", 1, 0, (struct sockaddr *)&ipv4, sizeof(ipv4)) == 1, "UDP send accepts before asynchronous error arrives");
    require(epoll_wait(epoll_fd, &ready, 1, WAIT_MS) == 1 && (ready.events & EPOLLERR), "UDP pending send error arrives");
    require(sendto(fd, "X", 1, 0, (struct sockaddr *)&ipv4, sizeof(ipv4)) < 0 && errno == EACCES, "external UDP send consumes pending asynchronous error");
    int error;
    socklen_t error_length = sizeof(error);
    require(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_length) == 0 && error == 0, "UDP send consumes asynchronous error exactly once");
    close(epoll_fd);
    int local_server = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(local_server >= 0, "mixed-path local UDP server");
    require(setsockopt(local_server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "mixed-path local UDP server deadline");
    struct sockaddr_in local = ipv4_address("127.0.0.2", 0);
    require(bind(local_server, (struct sockaddr *)&local, sizeof(local)) == 0, "mixed-path local UDP bind");
    local.sin_port = htons(read_port(local_server));
    trace_phase("SOCKET_PHASE blocking_denial_native_send");
    require(sendto(fd, "N", 1, 0, (struct sockaddr *)&local, sizeof(local)) == 1, "local UDP send succeeds after blocking broker denial");
    trace_phase("SOCKET_PHASE blocking_denial_native_sent");
    struct sockaddr_in source;
    socklen_t source_length = sizeof(source);
    char reply;
    require(recvfrom(local_server, &reply, 1, 0, (struct sockaddr *)&source, &source_length) == 1 && reply == 'N', "mixed-path local UDP delivery");
    require(source_length == sizeof(source) && source.sin_family == AF_INET && source.sin_port == htons(bound_port), "mixed-path native UDP preserves the external local port");
    trace_phase("SOCKET_PHASE blocking_denial_native_delivered");
    struct timeval delayed_timeout = {.tv_sec = 5};
    require(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &delayed_timeout, sizeof(delayed_timeout)) == 0, "delayed native UDP receive deadline");
    pid_t child = fork();
    require(child >= 0, "delayed native UDP reply child");
    if (child == 0) {
        usleep(100000);
        require(sendto(local_server, "R", 1, 0, (struct sockaddr *)&source, source_length) == 1, "delayed mixed-path local UDP reply");
        _exit(0);
    }
    trace_phase("SOCKET_PHASE blocking_denial_native_receive");
    struct timespec started, completed;
    require(clock_gettime(CLOCK_MONOTONIC, &started) == 0, "delayed native receive start");
    source_length = sizeof(source);
    require(recvfrom(fd, &reply, 1, 0, (struct sockaddr *)&source, &source_length) == 1 && reply == 'R', "native arrival wakes mixed-path blocking UDP receive");
    require(clock_gettime(CLOCK_MONOTONIC, &completed) == 0, "delayed native receive completion");
    long long elapsed_ns = (long long)(completed.tv_sec - started.tv_sec) * 1000000000LL + completed.tv_nsec - started.tv_nsec;
    require(elapsed_ns < 2000000000LL, "native arrival wakes mixed-path UDP before socket timeout");
    require(source_length == sizeof(source) && source.sin_family == AF_INET && source.sin_addr.s_addr == local.sin_addr.s_addr && source.sin_port == local.sin_port, "mixed-path native UDP reply source identity");
    require(read_port(fd) == bound_port, "mixed-path UDP keeps its bound local port");
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "delayed native UDP reply status");
    trace_phase("SOCKET_PHASE blocking_denial_native_received");
    close(local_server);
    close(fd);
    puts("SOCKET_ERRORS_OK");
}

static void exercise_nonblocking_receive(int fd) {
    struct timeval timeout = {.tv_sec = 5};
    require(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "concurrent blocking receive deadline");
    int ready[2];
    require(pipe(ready) == 0, "concurrent receive synchronization pipe");
    pid_t child = fork();
    require(child >= 0, "concurrent blocking receive child");
    char reply;
    if (child == 0) {
        close(ready[0]);
        require(write(ready[1], "R", 1) == 1, "concurrent blocking receive ready");
        close(ready[1]);
        require(recv(fd, &reply, 1, 0) < 0 && errno == EAGAIN, "concurrent blocking receive reaches socket timeout");
        close(fd);
        _exit(0);
    }
    close(ready[1]);
    require(read(ready[0], &reply, 1) == 1 && reply == 'R', "concurrent blocking receive startup");
    close(ready[0]);
    usleep(100000);
    struct timespec started, completed;
    require(clock_gettime(CLOCK_MONOTONIC, &started) == 0, "concurrent nonblocking receive start");
    ssize_t count = recv(fd, &reply, 1, MSG_DONTWAIT);
    int receive_error = errno;
    require(clock_gettime(CLOCK_MONOTONIC, &completed) == 0, "concurrent nonblocking receive completion");
    long long elapsed_ns = (long long)(completed.tv_sec - started.tv_sec) * 1000000000LL + completed.tv_nsec - started.tv_nsec;
    printf("SOCKET_NONBLOCKING_RECEIVE count=%zd errno=%d elapsed_ns=%lld\n", count, receive_error, elapsed_ns);
    fflush(stdout);
    require(count < 0 && receive_error == EAGAIN, "nonblocking receive returns EAGAIN behind another reader");
    require(elapsed_ns < 2000000000LL, "nonblocking receive never waits for another reader");
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "concurrent blocking receive child status");
    puts("SOCKET_RECEIVE_CONCURRENCY_OK");
}

static void exercise_udp_error_budget(const char *ip, unsigned short port) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    require(fd >= 0, "UDP error budget socket");
    int enabled = 1;
    require(setsockopt(fd, SOL_IP, IP_RECVERR, &enabled, sizeof(enabled)) == 0, "enable retained UDP errors");
    int receive_bytes = 8192;
    require(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive_bytes, sizeof(receive_bytes)) == 0, "large UDP error accumulation budget");
    struct sockaddr_in denied = ipv4_address("192.0.2.90", 80);
    enum { RETAINED_DENIALS = 8 };
    for (unsigned int index = 0; index < RETAINED_DENIALS; index++) {
        require(sendto(fd, "E", 1, 0, (struct sockaddr *)&denied, sizeof(denied)) == 1, "accumulate denied UDP request");
        consume_udp_denial(fd);
    }
    receive_bytes = 1024;
    require(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive_bytes, sizeof(receive_bytes)) == 0, "shrink UDP receive budget below retained errors");
    static const char request[] = "TERRA_ERRQUEUE_RESUME";
    struct sockaddr_in peer = ipv4_address(ip, port);
    require(sendto(fd, request, sizeof(request) - 1, 0, (struct sockaddr *)&peer, sizeof(peer)) == (ssize_t)(sizeof(request) - 1), "one allowed reply behind retained UDP errors");
    unsigned int waited = 0;
    while (access("/work/UDP_ERROR_REPLY_SENT", F_OK) != 0 && waited++ < WAIT_MS / 10)
        usleep(10000);
    require(access("/work/UDP_ERROR_REPLY_SENT", F_OK) == 0, "host sent the allowed UDP reply");
    char reply[sizeof(request)];
    for (unsigned int interval = 0; interval < 10; interval++) {
        usleep(100000);
        require(recv(fd, reply, sizeof(reply), MSG_PEEK | MSG_DONTWAIT) < 0 && errno == EAGAIN, "allowed reply remains behind retained UDP error memory");
    }
    trace_phase("SOCKET_ERROR_QUEUE_BUDGET_PAUSED");
    for (unsigned int index = 0; index < RETAINED_DENIALS; index++)
        consume_datagram_error(fd, (struct sockaddr *)&denied, sizeof(denied));
    struct msghdr message = {0};
    require(recvmsg(fd, &message, MSG_ERRQUEUE | MSG_DONTWAIT) < 0 && errno == EAGAIN, "all retained UDP errors consumed without another send");
    int error;
    socklen_t error_length = sizeof(error);
    require(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_length) == 0 && error == 0, "retained UDP error state cleared");
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    require(epoll_fd >= 0, "UDP error budget readiness descriptor");
    struct epoll_event ready = {.events = EPOLLIN, .data.fd = fd};
    require(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ready) == 0, "wait for UDP error consumption progress");
    require(epoll_wait(epoll_fd, &ready, 1, WAIT_MS) == 1 && (ready.events & EPOLLIN), "error queue consumption resumes the buffered allowed reply");
    require(recv(fd, reply, sizeof(reply), MSG_DONTWAIT) == (ssize_t)(sizeof(request) - 1) && memcmp(reply, request, sizeof(request) - 1) == 0, "buffered UDP reply preserved without another send");
    close(epoll_fd);
    close(fd);
    puts("SOCKET_ERROR_QUEUE_BUDGET_OK");
}

static void exercise_udp_native_first(const char *ip, unsigned short port) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int sender = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(fd >= 0 && sender >= 0, "mixed UDP sockets");
    struct sockaddr_in local = ipv4_address("0.0.0.0", 0);
    require(bind(fd, (struct sockaddr *)&local, sizeof(local)) == 0, "mixed UDP wildcard bind");
    local = ipv4_address("127.0.0.1", read_port(fd));
    struct sockaddr_in peer = ipv4_address(ip, port);
    struct timeval timeout = {.tv_sec = 10};
    require(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "mixed UDP receive deadline");
    require(sendto(fd, "HOST", 4, 0, (struct sockaddr *)&peer, sizeof(peer)) == 4, "mixed UDP external send");
    char reply[4];
    require(recv(fd, reply, sizeof(reply), MSG_PEEK) == 4 && memcmp(reply, "HOST", 4) == 0, "mixed UDP virtual data queued");
    require(read_port(fd) == ntohs(local.sin_port), "external UDP opening preserves the explicit local port");
    require(sendto(sender, "N", 1, 0, (struct sockaddr *)&local, sizeof(local)) == 1, "mixed UDP native data queued");
    require(recv(fd, reply, sizeof(reply), MSG_PEEK | MSG_DONTWAIT) == 1 && reply[0] == 'N', "mixed UDP native receive priority");
    int available = -1;
    require(ioctl(fd, FIONREAD, &available) == 0 && available == 1, "mixed UDP ioctl follows native receive priority");
    struct sockaddr_in source;
    socklen_t source_length = sizeof(source);
    require(recvfrom(fd, reply, sizeof(reply), MSG_DONTWAIT, (struct sockaddr *)&source, &source_length) == 1 && reply[0] == 'N', "mixed UDP consume native data");
    require(source_length == sizeof(source) && source.sin_family == AF_INET && source.sin_addr.s_addr == local.sin_addr.s_addr && source.sin_port == htons(read_port(sender)), "mixed UDP native reply source identity");
    require(read_port(fd) == ntohs(local.sin_port), "mixed UDP native receive preserves the local port");
    require(ioctl(fd, FIONREAD, &available) == 0 && available == 4, "mixed UDP virtual data remains queued");
    require(recv(fd, reply, sizeof(reply), MSG_DONTWAIT) == 4 && memcmp(reply, "HOST", 4) == 0, "mixed UDP ioctl preserves virtual data");
    close(sender);
    close(fd);
}

static void exercise_udp_receive_budget(const char *ip, unsigned short port) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    int sender = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(fd >= 0 && sender >= 0, "mixed UDP receive budget sockets");
    struct timeval timeout = {.tv_sec = 5};
    require(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "mixed UDP receive budget deadline");
    struct sockaddr_in peer = ipv4_address(ip, port);
    require(sendto(fd, "O", 1, 0, (struct sockaddr *)&peer, sizeof(peer)) == 1, "open mixed UDP receive budget carrier");
    char reply;
    require(recv(fd, &reply, 1, 0) == 1 && reply == 'O', "mixed UDP receive budget carrier ready");
    int receive_bytes = 1024;
    require(setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive_bytes, sizeof(receive_bytes)) == 0, "small mixed UDP receive budget");
    struct sockaddr_in local = ipv4_address("127.0.0.2", read_port(fd));
    for (unsigned int index = 0; index < 16; index++)
        require(sendto(sender, "N", 1, 0, (struct sockaddr *)&local, sizeof(local)) == 1, "fill native UDP receive budget");
    require(sendto(fd, "E", 1, 0, (struct sockaddr *)&peer, sizeof(peer)) == 1, "queue external UDP behind native receive budget");
    usleep(100000);
    unsigned int native_replies = 0;
    for (;;) {
        require(recv(fd, &reply, 1, 0) == 1, "native receives resume external UDP draining");
        if (reply == 'E')
            break;
        require(reply == 'N' && ++native_replies <= 16, "mixed UDP receive budget preserves native datagrams");
    }
    require(native_replies > 0, "native UDP occupied the receive budget before external reply");
    close(sender);
    close(fd);
}

static void set_quic_option(int fd, int level, int option, int value) {
    require(setsockopt(fd, level, option, &value, sizeof(value)) == 0, "set QUIC socket option");
    int actual = -1;
    socklen_t length = sizeof(actual);
    require(getsockopt(fd, level, option, &actual, &length) == 0 &&
            length == sizeof(actual) && actual == value, "QUIC socket option readback");
}

static void configure_quic_options(int fd, int family) {
    set_quic_option(fd, SOL_SOCKET, SO_BROADCAST, 1);
    if (family == AF_INET) {
        set_quic_option(fd, SOL_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO);
        set_quic_option(fd, SOL_IP, IP_RECVTOS, 1);
        set_quic_option(fd, SOL_IP, IP_PKTINFO, 1);
        set_quic_option(fd, SOL_IP, IP_TOS, 2);
    } else {
        set_quic_option(fd, SOL_IPV6, IPV6_MTU_DISCOVER, IPV6_PMTUDISC_DO);
        set_quic_option(fd, SOL_IPV6, IPV6_DONTFRAG, 1);
        set_quic_option(fd, SOL_IPV6, IPV6_RECVTCLASS, 1);
        set_quic_option(fd, SOL_IPV6, IPV6_RECVPKTINFO, 1);
        set_quic_option(fd, SOL_IPV6, IPV6_TCLASS, 2);
    }
    set_quic_option(fd, SOL_UDP, UDP_GRO, 1);
    set_quic_option(fd, SOL_UDP, UDP_SEGMENT, 0);
}

static ssize_t send_quic_control(int fd, const struct sockaddr *peer, socklen_t peer_length,
                                 const void *payload, size_t length, int level, int option,
                                 const void *value, size_t value_length) {
    union {
        struct cmsghdr alignment;
        unsigned char bytes[CMSG_SPACE(sizeof(struct in6_pktinfo))];
    } control = {0};
    require(value_length <= sizeof(struct in6_pktinfo), "QUIC control message bound");
    struct iovec bytes[2] = {
        {.iov_base = (void *)payload, .iov_len = length / 2},
        {.iov_base = (unsigned char *)payload + length / 2, .iov_len = length - length / 2},
    };
    struct msghdr message = {
        .msg_name = (void *)peer,
        .msg_namelen = peer_length,
        .msg_iov = bytes,
        .msg_iovlen = 2,
        .msg_control = control.bytes,
        .msg_controllen = CMSG_SPACE(value_length),
    };
    struct cmsghdr *entry = CMSG_FIRSTHDR(&message);
    entry->cmsg_level = level;
    entry->cmsg_type = option;
    entry->cmsg_len = CMSG_LEN(value_length);
    memcpy(CMSG_DATA(entry), value, value_length);
    return sendmsg(fd, &message, 0);
}

static void receive_quic_payload(int fd, const unsigned char *expected, size_t length,
                                  int expected_ecn) {
    unsigned char reply[4097];
    union {
        struct cmsghdr alignment;
        unsigned char bytes[256];
    } control;
    struct iovec bytes = {.iov_base = reply, .iov_len = sizeof(reply)};
    struct msghdr message = {
        .msg_iov = &bytes,
        .msg_iovlen = 1,
        .msg_control = control.bytes,
        .msg_controllen = sizeof(control.bytes),
    };
    require(recvmsg(fd, &message, MSG_TRUNC) == (ssize_t)length &&
            !(message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) &&
            memcmp(reply, expected, length) == 0, "QUIC datagram boundary and payload integrity");
    int saw_ecn = 0;
    for (struct cmsghdr *entry = CMSG_FIRSTHDR(&message); entry; entry = CMSG_NXTHDR(&message, entry)) {
        require(!(entry->cmsg_level == SOL_UDP && entry->cmsg_type == UDP_GRO), "QUIC receive stays uncoalesced");
        if ((entry->cmsg_level == SOL_IP && entry->cmsg_type == IP_TOS) ||
            (entry->cmsg_level == SOL_IPV6 && entry->cmsg_type == IPV6_TCLASS)) {
            require(expected_ecn >= 0, "external QUIC receive omits ECN metadata");
            int actual = 0;
            size_t value_length = entry->cmsg_level == SOL_IP ? sizeof(unsigned char) : sizeof(int);
            require(entry->cmsg_len == CMSG_LEN(value_length), "native QUIC ECN control shape");
            memcpy(&actual, CMSG_DATA(entry), value_length);
            require(actual == expected_ecn, "native QUIC preserves ECN codepoint");
            saw_ecn = 1;
        }
    }
    require(expected_ecn < 0 || saw_ecn, "native QUIC delivers ECN metadata");
}

static void exercise_quic_native(int fd, int family, const unsigned char *payload) {
    int receiver = socket(family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(receiver >= 0, "native QUIC receiver socket");
    struct timeval timeout = {.tv_sec = 5};
    require(setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
            "native QUIC receive deadline");
    struct sockaddr_storage local = {0};
    socklen_t local_length;
    int level, option;
    if (family == AF_INET) {
        struct sockaddr_in *address = (void *)&local;
        *address = ipv4_address("127.0.0.2", 0);
        local_length = sizeof(*address);
        level = SOL_IP;
        option = IP_TOS;
        set_quic_option(receiver, SOL_IP, IP_RECVTOS, 1);
    } else {
        struct sockaddr_in6 *address = (void *)&local;
        address->sin6_family = AF_INET6;
        address->sin6_addr = in6addr_loopback;
        local_length = sizeof(*address);
        level = SOL_IPV6;
        option = IPV6_TCLASS;
        set_quic_option(receiver, SOL_IPV6, IPV6_RECVTCLASS, 1);
    }
    require(bind(receiver, (struct sockaddr *)&local, local_length) == 0 &&
            getsockname(receiver, (struct sockaddr *)&local, &local_length) == 0,
            "native QUIC receiver address");
    int ecn = 1;
    require(send_quic_control(fd, (struct sockaddr *)&local, local_length, payload, 7,
                             level, option, &ecn, sizeof(ecn)) == 7, "native QUIC ECN send");
    receive_quic_payload(receiver, payload, 7, ecn);
    unsigned short segment = 1200;
    require(send_quic_control(fd, (struct sockaddr *)&local, local_length, payload, 3600,
                             SOL_UDP, UDP_SEGMENT, &segment, sizeof(segment)) == 3600,
            "native QUIC GSO send");
    for (unsigned int index = 0; index < 3; index++)
        receive_quic_payload(receiver, payload + index * segment, segment, 2);
    close(receiver);
}

static void exercise_quic_family(const struct sockaddr *peer, socklen_t peer_length) {
    int fd = socket(peer->sa_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(fd >= 0, "external QUIC socket");
    struct timeval timeout = {.tv_sec = 5};
    require(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0,
            "external QUIC deadlines");
    unsigned char payload[6000];
    for (size_t index = 0; index < sizeof(payload); index++)
        payload[index] = (unsigned char)((index * 17 + index / 1200) % 251);
    int level = peer->sa_family == AF_INET ? SOL_IP : SOL_IPV6;
    int unsupported_option = peer->sa_family == AF_INET ? IP_RECVTTL : IPV6_RECVHOPLIMIT;
    int enabled = 1;
    require(setsockopt(fd, level, unsupported_option, &enabled, sizeof(enabled)) == -1 &&
            errno == ENOPROTOOPT, "unsupported QUIC option rejected before first send");
    configure_quic_options(fd, peer->sa_family);
    require(sendto(fd, payload, 7, 0, peer, peer_length) == 7, "QUIC options before first send");
    receive_quic_payload(fd, payload, 7, -1);
    require(setsockopt(fd, level, unsupported_option, &enabled, sizeof(enabled)) == -1 &&
            errno == ENOPROTOOPT, "unsupported QUIC option rejected after first send");
    configure_quic_options(fd, peer->sa_family);
    require(sendto(fd, payload, 7, 0, peer, peer_length) == 7, "QUIC options after first send");
    receive_quic_payload(fd, payload, 7, -1);
    if (peer->sa_family == AF_INET) {
        int mtu;
        socklen_t mtu_length = sizeof(mtu);
        require(getsockopt(fd, SOL_IP, IP_MTU, &mtu, &mtu_length) == -1 &&
                errno == ENOPROTOOPT, "external QUIC path MTU query stays refused");
    }
    int ecn = 2;
    int option = peer->sa_family == AF_INET ? IP_TOS : IPV6_TCLASS;
    require(send_quic_control(fd, peer, peer_length, payload, 7, level, option,
                             &ecn, sizeof(ecn)) == 7, "external QUIC ECN control send");
    receive_quic_payload(fd, payload, 7, -1);
    if (peer->sa_family == AF_INET) {
        unsigned char codepoint = 2;
        require(send_quic_control(fd, peer, peer_length, payload, 7, level, option,
                                 &codepoint, sizeof(codepoint)) == 7, "external QUIC byte ECN control send");
        receive_quic_payload(fd, payload, 7, -1);
    }
    require(send_quic_control(fd, peer, peer_length, payload, 7, level, option,
                             &ecn, 0) == -1 && errno == EINVAL, "malformed QUIC ECN control rejected");
    set_quic_option(fd, SOL_UDP, UDP_SEGMENT, 1000);
    unsigned short segment = 1200;
    require(send_quic_control(fd, peer, peer_length, payload, 3600, SOL_UDP,
                             UDP_SEGMENT, &segment, sizeof(segment)) == 3600,
            "QUIC GSO control overrides the socket default");
    for (unsigned int index = 0; index < 3; index++)
        receive_quic_payload(fd, payload + index * segment, segment, -1);
    require(send_quic_control(fd, peer, peer_length, payload, sizeof(payload), SOL_UDP,
                             UDP_SEGMENT, &segment, sizeof(segment)) == sizeof(payload),
            "QUIC GSO payload exceeds a single external datagram");
    for (unsigned int index = 0; index < 5; index++)
        receive_quic_payload(fd, payload + index * segment, segment, -1);
    require(sendto(fd, payload, 2401, 0, peer, peer_length) == 2401, "QUIC socket default GSO send");
    receive_quic_payload(fd, payload, 1000, -1);
    receive_quic_payload(fd, payload + 1000, 1000, -1);
    receive_quic_payload(fd, payload + 2000, 401, -1);
    set_quic_option(fd, SOL_UDP, UDP_SEGMENT, 0);
    require(send_quic_control(fd, peer, peer_length, payload, 7, 0x7fff, 1,
                             &ecn, sizeof(ecn)) == -1 && errno == EOPNOTSUPP,
            "unknown QUIC control level rejected");
    segment = 0;
    require(send_quic_control(fd, peer, peer_length, payload, 7, SOL_UDP, UDP_SEGMENT,
                             &segment, sizeof(segment)) == -1 && errno == EINVAL,
            "zero QUIC GSO control rejected");
    segment = 4097;
    require(send_quic_control(fd, peer, peer_length, payload, 7, SOL_UDP, UDP_SEGMENT,
                             &segment, sizeof(segment)) == -1 && errno == EINVAL,
            "oversized QUIC GSO segment rejected");
    segment = 1;
    require(send_quic_control(fd, peer, peer_length, payload, 65, SOL_UDP, UDP_SEGMENT,
                             &segment, sizeof(segment)) == -1 && errno == EINVAL,
            "more than 64 QUIC GSO segments rejected");
    unsigned char *oversized_batch = calloc(64, 4096);
    require(oversized_batch != NULL, "oversized QUIC GSO batch allocation");
    segment = 4096;
    require(send_quic_control(fd, peer, peer_length, oversized_batch, 64 * 4096,
                             SOL_UDP, UDP_SEGMENT, &segment, sizeof(segment)) == -1 &&
            errno == EMSGSIZE, "QUIC GSO batch that cannot fit is rejected atomically");
    free(oversized_batch);
    if (peer->sa_family == AF_INET) {
        struct in_pktinfo packet = {0};
        require(send_quic_control(fd, peer, peer_length, payload, 7, SOL_IP, IP_PKTINFO,
                                 &packet, sizeof(packet)) == 7, "unspecified QUIC IPv4 source accepted");
        receive_quic_payload(fd, payload, 7, -1);
        require(inet_pton(AF_INET, "192.0.2.91", &packet.ipi_spec_dst) == 1, "foreign QUIC IPv4 source");
        require(send_quic_control(fd, peer, peer_length, payload, 7, SOL_IP, IP_PKTINFO,
                                 &packet, sizeof(packet)) == -1 && errno == EINVAL,
                "foreign QUIC IPv4 source rejected");
    } else {
        struct in6_pktinfo packet = {0};
        require(send_quic_control(fd, peer, peer_length, payload, 7, SOL_IPV6, IPV6_PKTINFO,
                                 &packet, sizeof(packet)) == 7, "unspecified QUIC IPv6 source accepted");
        receive_quic_payload(fd, payload, 7, -1);
        require(inet_pton(AF_INET6, "2001:db8::91", &packet.ipi6_addr) == 1, "foreign QUIC IPv6 source");
        require(send_quic_control(fd, peer, peer_length, payload, 7, SOL_IPV6, IPV6_PKTINFO,
                                 &packet, sizeof(packet)) == -1 && errno == EINVAL,
                "foreign QUIC IPv6 source rejected");
    }
    require(sendto(fd, payload + 100, 7, 0, peer, peer_length) == 7, "QUIC socket survives rejected controls");
    receive_quic_payload(fd, payload + 100, 7, -1);
    struct sockaddr_storage denied = {0};
    if (peer->sa_family == AF_INET) {
        *(struct sockaddr_in *)&denied = ipv4_address("192.0.2.90", 80);
        set_quic_option(fd, SOL_IP, IP_RECVERR, 1);
    } else {
        struct sockaddr_in6 *address = (void *)&denied;
        address->sin6_family = AF_INET6;
        address->sin6_port = htons(80);
        require(inet_pton(AF_INET6, "2001:db8::90", &address->sin6_addr) == 1, "denied QUIC IPv6 destination");
        set_quic_option(fd, SOL_IPV6, IPV6_RECVERR, 1);
    }
    segment = 1200;
    require(send_quic_control(fd, (struct sockaddr *)&denied, peer_length, payload, 7,
                             SOL_UDP, UDP_SEGMENT, &segment, sizeof(segment)) == 7,
            "denied QUIC GSO send accepted asynchronously");
    consume_udp_denial(fd);
    consume_datagram_error(fd, (struct sockaddr *)&denied, peer_length);
    exercise_quic_native(fd, peer->sa_family, payload);
    close(fd);
}

static void exercise_quic_socket(const char *ip, unsigned short port) {
    struct sockaddr_in peer = ipv4_address(ip, port);
    exercise_quic_family((struct sockaddr *)&peer, sizeof(peer));
    struct sockaddr_in6 peer6 = {.sin6_family = AF_INET6, .sin6_port = htons(port)};
    require(inet_pton(AF_INET6, "fd53:4d00::1", &peer6.sin6_addr) == 1, "external QUIC IPv6 peer");
    exercise_quic_family((struct sockaddr *)&peer6, sizeof(peer6));
    puts("SOCKET_QUIC_OK");
}

static void wait_for_quic_credit_marker(const char *path) {
    unsigned int waited = 0;
    while (access(path, F_OK) != 0 && waited++ < WAIT_MS / 10)
        usleep(10000);
    require(access(path, F_OK) == 0, "one-way QUIC credit sink progress");
}

static void exercise_quic_credit(const char *ip, unsigned short port) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(fd >= 0, "one-way QUIC credit socket");
    struct timeval timeout = {.tv_sec = 5};
    require(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0,
            "one-way QUIC credit send deadline");
    struct sockaddr_in peer = ipv4_address(ip, port);
    require(sendto(fd, "CREDIT!", 7, 0, (struct sockaddr *)&peer, sizeof(peer)) == 7,
            "one-way QUIC credit prefix send");
    wait_for_quic_credit_marker("/work/UDP_CREDIT_FIRST_RECEIVED");
    unsigned char payload[40 * 1200];
    for (size_t index = 0; index < sizeof(payload); index++)
        payload[index] = (unsigned char)((index * 17 + index / 1200) % 251);
    unsigned short segment = 1200;
    struct timespec started, completed;
    require(clock_gettime(CLOCK_MONOTONIC, &started) == 0, "one-way QUIC credit send start");
    require(send_quic_control(fd, (struct sockaddr *)&peer, sizeof(peer), payload, sizeof(payload),
                             SOL_UDP, UDP_SEGMENT, &segment, sizeof(segment)) == sizeof(payload),
            "blocking QUIC GSO requests enough credit for the complete batch");
    require(clock_gettime(CLOCK_MONOTONIC, &completed) == 0, "one-way QUIC credit send completion");
    long long elapsed_ns = (long long)(completed.tv_sec - started.tv_sec) * 1000000000LL + completed.tv_nsec - started.tv_nsec;
    require(elapsed_ns < 5000000000LL, "blocking QUIC GSO completes within its send deadline");
    wait_for_quic_credit_marker("/work/UDP_CREDIT_BATCH_RECEIVED");
    close(fd);
    printf("SOCKET_QUIC_CREDIT_OK elapsed_ns=%lld\n", elapsed_ns);
}

static void exercise_udp(const char *ip, unsigned short first, unsigned short second) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(fd >= 0, "unconnected UDP socket");
    struct timeval timeout = {.tv_sec = 10};
    require(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "UDP receive deadline");
    int enabled = 1;
    require(setsockopt(fd, SOL_IP, IP_PKTINFO, &enabled, sizeof(enabled)) == 0, "enable UDP packet info");
    require_option(fd, SOL_IP, IP_PKTINFO);
    for (unsigned int index = 0; index < 4; index++) {
        struct sockaddr_in peer = ipv4_address(ip, index % 2 ? second : first);
        size_t length = index == 3 ? 0 : index + 1;
        unsigned char bytes[] = {1, 2, 3}, reply[4];
        require(sendto(fd, bytes, length, 0, (struct sockaddr *)&peer, sizeof(peer)) == (ssize_t)length, "UDP per-datagram destination");
        require(recv(fd, reply, sizeof(reply), MSG_PEEK) == (ssize_t)length, "UDP peek preserves queued datagram");
        if (length > 1) {
            struct iovec truncated = {.iov_base = reply, .iov_len = 1};
            struct msghdr peek = {.msg_iov = &truncated, .msg_iovlen = 1};
            require(recvmsg(fd, &peek, MSG_PEEK | MSG_TRUNC) == (ssize_t)length && (peek.msg_flags & MSG_TRUNC), "UDP truncated peek returns full datagram length without consuming it");
        }
        int available = -1;
        require(ioctl(fd, FIONREAD, &available) == 0 && available == (int)length, "UDP FIONREAD reports queued datagram length");
        struct sockaddr_in source;
        struct iovec payload = {.iov_base = reply, .iov_len = sizeof(reply)};
        union {
            struct cmsghdr alignment;
            unsigned char bytes[CMSG_SPACE(sizeof(struct in_pktinfo))];
        } control;
        struct msghdr message = {
            .msg_name = &source,
            .msg_namelen = sizeof(source),
            .msg_iov = &payload,
            .msg_iovlen = 1,
            .msg_control = control.bytes,
            .msg_controllen = sizeof(control.bytes),
        };
        ssize_t received = recvmsg(fd, &message, 0);
        require(received == (ssize_t)length && memcmp(bytes, reply, length) == 0, "UDP preserves boundaries and empty datagrams");
        require(message.msg_namelen == sizeof(source) && source.sin_port == peer.sin_port && source.sin_addr.s_addr == peer.sin_addr.s_addr, "UDP reply source identity");
        struct cmsghdr *entry = CMSG_FIRSTHDR(&message);
        require(!(message.msg_flags & MSG_CTRUNC) && entry && entry->cmsg_level == SOL_IP && entry->cmsg_type == IP_PKTINFO && entry->cmsg_len == CMSG_LEN(sizeof(struct in_pktinfo)), "UDP receive packet info");
        const struct in_pktinfo *packet = (const void *)CMSG_DATA(entry);
        if (packet->ipi_ifindex == 0) {
            struct sockaddr_in local;
            socklen_t local_length = sizeof(local);
            require(getsockname(fd, (struct sockaddr *)&local, &local_length) == 0 && local_length == sizeof(local), "virtual UDP bound endpoint");
            require(packet->ipi_addr.s_addr == local.sin_addr.s_addr && packet->ipi_spec_dst.s_addr == local.sin_addr.s_addr, "virtual packet info preserves guest bound endpoint");
        }
    }
    struct sockaddr_in peer = ipv4_address(ip, first);
    require(connect(fd, (struct sockaddr *)&peer, sizeof(peer)) == 0, "UDP connect");
    require_option(fd, SOL_IP, IP_PKTINFO);
    require(send(fd, "C", 1, 0) == 1, "connected UDP send");
    char reply;
    require(recv(fd, &reply, 1, 0) == 1 && reply == 'C', "connected UDP response");
    exercise_nonblocking_receive(fd);
    require(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "restore UDP receive deadline");
    int local_sender = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(local_sender >= 0, "unrelated local UDP sender");
    require(setsockopt(local_sender, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "local UDP sender receive deadline");
    struct sockaddr_in local = ipv4_address("127.0.0.2", 0);
    require(bind(local_sender, (struct sockaddr *)&local, sizeof(local)) == 0, "local UDP sender bind");
    struct sockaddr_in target = ipv4_address("127.0.0.2", read_port(fd));
    require(sendto(local_sender, "L", 1, 0, (struct sockaddr *)&target, sizeof(target)) == 1, "inject unrelated local datagram into external connected port");
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    require(epoll_fd >= 0, "connected UDP filter epoll descriptor");
    struct epoll_event event = {.events = EPOLLIN, .data.fd = fd};
    require(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) == 0, "register connected UDP filtering readiness");
    int count;
    do {
        count = epoll_wait(epoll_fd, &event, 1, 100);
    } while (count < 0 && errno == EINTR);
    require(count == 0, "external connected UDP rejects unrelated local receive readiness");
    require(recv(fd, &reply, 1, MSG_DONTWAIT) < 0 && errno == EAGAIN, "external connected UDP rejects unrelated local datagram");
    close(epoll_fd);
    struct sockaddr_in denied = ipv4_address("192.0.2.90", 80);
    trace_phase("SOCKET_PHASE denied_reconnect");
    require(connect(fd, (struct sockaddr *)&denied, sizeof(denied)) == 0, "connected UDP reconnect is guest-local state");
    struct sockaddr_in retained;
    socklen_t retained_length = sizeof(retained);
    require(getpeername(fd, (struct sockaddr *)&retained, &retained_length) == 0 && retained_length == sizeof(retained) && retained.sin_addr.s_addr == denied.sin_addr.s_addr && retained.sin_port == denied.sin_port, "UDP reconnect reports the new peer");
    require(send(fd, "X", 1, 0) == 1, "denied connected UDP send is accepted");
    require(recv(fd, &reply, 1, 0) < 0 && errno == EACCES, "denied connected UDP send reports the asynchronous denial");
    trace_phase("SOCKET_PHASE denied_reconnect_returned");
    require(connect(fd, (struct sockaddr *)&peer, sizeof(peer)) == 0, "UDP reconnect to the authorized peer");
    trace_phase("SOCKET_PHASE denied_reconnect_peer_retained");
    require(send(fd, "F", 1, 0) == 1, "UDP send uses the authorized peer after a denial");
    trace_phase("SOCKET_PHASE denied_reconnect_sent");
    require(recv(fd, &reply, 1, 0) == 1 && reply == 'F', "UDP receive uses the authorized peer after a denial");
    trace_phase("SOCKET_PHASE denied_reconnect_received");
    struct sockaddr disconnected = {.sa_family = AF_UNSPEC};
    require(connect(fd, &disconnected, sizeof(disconnected)) == 0, "UDP disconnect");
    trace_phase("SOCKET_PHASE denied_reconnect_disconnected");
    local.sin_port = htons(read_port(local_sender));
    require(sendto(fd, "D", 1, 0, (struct sockaddr *)&local, sizeof(local)) == 1, "disconnected UDP sends through guest local route");
    trace_phase("SOCKET_PHASE denied_reconnect_native_sent");
    socklen_t source_length = sizeof(target);
    require(recvfrom(local_sender, &reply, 1, 0, (struct sockaddr *)&target, &source_length) == 1 && reply == 'D', "disconnected UDP native source delivery");
    require(sendto(local_sender, "R", 1, 0, (struct sockaddr *)&target, source_length) == 1, "local reply to disconnected UDP socket");
    trace_phase("SOCKET_PHASE denied_reconnect_native_receive");
    require(recv(fd, &reply, 1, 0) == 1 && reply == 'R', "UDP disconnect restores native wildcard receive");
    trace_phase("SOCKET_PHASE denied_reconnect_native_received");
    close(local_sender);
    close(fd);
}

static void exercise_ipv6_udp_disconnect(const char *ip, unsigned short port, int mapped) {
    int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(fd >= 0, "mapped UDP disconnect socket");
    struct timeval timeout = {.tv_sec = 10};
    require(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "mapped UDP disconnect receive deadline");
    struct sockaddr_in6 wildcard = {.sin6_family = AF_INET6};
    require(bind(fd, (struct sockaddr *)&wildcard, sizeof(wildcard)) == 0, "explicit mapped UDP wildcard bind");
    struct sockaddr_in6 peer = {.sin6_family = AF_INET6, .sin6_port = htons(port)};
    if (mapped) {
        peer.sin6_addr.s6_addr[10] = 255;
        peer.sin6_addr.s6_addr[11] = 255;
        require(inet_pton(AF_INET, ip, &peer.sin6_addr.s6_addr[12]) == 1, "mapped UDP peer address");
    } else {
        require(inet_pton(AF_INET6, ip, &peer.sin6_addr) == 1, "IPv6 UDP peer address");
    }
    require(connect(fd, (struct sockaddr *)&peer, sizeof(peer)) == 0, "mapped UDP peer connect");
    require(send(fd, "M", 1, 0) == 1, "mapped UDP connected send");
    char reply;
    require(recv(fd, &reply, 1, 0) == 1 && reply == 'M', "mapped UDP connected reply");
    struct sockaddr_in6 bound;
    socklen_t bound_length = sizeof(bound);
    require(getsockname(fd, (struct sockaddr *)&bound, &bound_length) == 0 && bound_length == sizeof(bound), "dual-stack UDP bound endpoint");
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    require(epoll_fd >= 0, "dual-stack UDP filtering epoll descriptor");
    struct epoll_event event = {.events = EPOLLIN, .data.fd = fd};
    require(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) == 0, "dual-stack UDP filtering readiness");
    const char *sources[] = {"127.0.0.2", "127.0.0.1", "127.0.0.6"};
    for (unsigned int index = 0; index < sizeof(sources) / sizeof(sources[0]); index++) {
        int unrelated = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        require(unrelated >= 0, "IPv4 sender against connected dual-stack UDP");
        struct sockaddr_in attacker = ipv4_address(sources[index], port);
        require(bind(unrelated, (struct sockaddr *)&attacker, sizeof(attacker)) == 0, "unrelated IPv4 sender matches connected remote source port");
        struct sockaddr_in target = ipv4_address(sources[index], ntohs(bound.sin6_port));
        require(sendto(unrelated, "X", 1, 0, (struct sockaddr *)&target, sizeof(target)) == 1, "inject unrelated IPv4 datagram into connected dual-stack socket");
        int count;
        do {
            count = epoll_wait(epoll_fd, &event, 1, 100);
        } while (count < 0 && errno == EINTR);
        char label[128];
        snprintf(label, sizeof(label), "connected %s UDP rejects unrelated %s readiness", mapped ? "mapped" : "IPv6", sources[index]);
        require(count == 0, label);
        require(recv(fd, &reply, 1, MSG_DONTWAIT) < 0 && errno == EAGAIN, "connected dual-stack UDP rejects unrelated IPv4 datagram");
        close(unrelated);
    }
    close(epoll_fd);
    struct sockaddr disconnected = {.sa_family = AF_UNSPEC};
    require(connect(fd, &disconnected, sizeof(disconnected)) == 0, "mapped UDP disconnect");
    int server = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(server >= 0, "IPv6 local UDP server after mapped disconnect");
    require(setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "IPv6 local UDP server deadline");
    struct sockaddr_in6 local = {.sin6_family = AF_INET6};
    require(inet_pton(AF_INET6, "::1", &local.sin6_addr) == 1, "IPv6 disconnect local peer");
    require(bind(server, (struct sockaddr *)&local, sizeof(local)) == 0, "IPv6 disconnect local bind");
    socklen_t local_length = sizeof(local);
    require(getsockname(server, (struct sockaddr *)&local, &local_length) == 0 && local_length == sizeof(local), "IPv6 disconnect local endpoint");
    require(sendto(fd, "V", 1, 0, (struct sockaddr *)&local, sizeof(local)) == 1, "IPv6 native send after mapped disconnect");
    struct sockaddr_in6 source;
    socklen_t source_length = sizeof(source);
    require(recvfrom(server, &reply, 1, 0, (struct sockaddr *)&source, &source_length) == 1 && reply == 'V', "IPv6 native delivery after mapped disconnect");
    require(sendto(server, "R", 1, 0, (struct sockaddr *)&source, source_length) == 1, "IPv6 local reply after mapped disconnect");
    require(recv(fd, &reply, 1, 0) == 1 && reply == 'R', "mapped UDP disconnect clears IPv6 native peer filter");
    close(server);
    close(fd);
}

static void write_mapping(const char *path, const char *text) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    require(fd >= 0, "namespace mapping file");
    write_all(fd, (const unsigned char *)text, strlen(text));
    close(fd);
}

static void enter_network_namespace(void) {
    uid_t uid = getuid();
    gid_t gid = getgid();
    require(unshare(CLONE_NEWUSER | CLONE_NEWNET) == 0, "unprivileged network namespace");
    char mapping[64];
    write_mapping("/proc/self/setgroups", "deny\n");
    snprintf(mapping, sizeof(mapping), "0 %lu 1\n", (unsigned long)uid);
    write_mapping("/proc/self/uid_map", mapping);
    snprintf(mapping, sizeof(mapping), "0 %lu 1\n", (unsigned long)gid);
    write_mapping("/proc/self/gid_map", mapping);
    int control = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(control >= 0, "namespace interface socket");
    struct ifreq loopback = {.ifr_flags = IFF_UP};
    strcpy(loopback.ifr_name, "lo");
    require(ioctl(control, SIOCSIFFLAGS, &loopback) == 0, "namespace loopback enable");
    close(control);
}

static void exercise_namespaces(void) {
    struct sockaddr_in address = ipv4_address("127.0.0.2", 0);
    int parent_listener = create_listener((struct sockaddr *)&address, sizeof(address));
    unsigned short parent_port = read_port(parent_listener);
    pid_t child = fork();
    require(child >= 0, "namespace child");
    if (child == 0) {
        close(parent_listener);
        enter_network_namespace();
        exercise_refused_local(parent_port);
        address = ipv4_address("127.0.0.2", parent_port);
        int listener = create_listener((struct sockaddr *)&address, sizeof(address));
        close(listener);
        int tun = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
        require(tun >= 0, "rootless TUN access");
        struct ifreq interface = {.ifr_flags = IFF_TUN | IFF_NO_PI};
        require(ioctl(tun, TUNSETIFF, &interface) == 0, "rootless TUN creation in own namespace");
        close(tun);
        _exit(0);
    }
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "namespace port ownership and rootless TUN");
    close(parent_listener);
    puts("SOCKET_NAMESPACES_OK");
}

struct route_message {
    struct nlmsghdr header;
    union {
        struct rtmsg route;
        struct ifaddrmsg address;
        struct fib_rule_hdr rule;
        struct ifinfomsg link;
    } body;
    unsigned char attributes[256];
};

static void add_route_attribute(struct route_message *message, unsigned short type, const void *value, size_t length) {
    size_t offset = NLMSG_ALIGN(message->header.nlmsg_len);
    size_t attribute_length = RTA_LENGTH(length);
    require(offset + RTA_ALIGN(attribute_length) <= sizeof(*message), "route message bound");
    struct rtattr *attribute = (struct rtattr *)((unsigned char *)message + offset);
    attribute->rta_type = type;
    attribute->rta_len = (unsigned short)attribute_length;
    memcpy(RTA_DATA(attribute), value, length);
    message->header.nlmsg_len = (unsigned int)(offset + RTA_ALIGN(attribute_length));
}

static void submit_route_message(struct route_message *message) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    require(fd >= 0, "native routing netlink socket");
    message->header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    if (message->header.nlmsg_type == RTM_NEWROUTE || message->header.nlmsg_type == RTM_NEWADDR || message->header.nlmsg_type == RTM_NEWRULE || message->header.nlmsg_type == RTM_NEWLINK)
        message->header.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
    message->header.nlmsg_seq = 1;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    require(sendto(fd, message, message->header.nlmsg_len, 0, (struct sockaddr *)&kernel, sizeof(kernel)) == (ssize_t)message->header.nlmsg_len, "submit guest route");
    unsigned char response[4096];
    ssize_t count = recv(fd, response, sizeof(response), 0);
    require(count >= (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr)), "routing acknowledgement length");
    struct nlmsghdr *header = (struct nlmsghdr *)response;
    require(header->nlmsg_type == NLMSG_ERROR && header->nlmsg_seq == 1, "routing acknowledgement shape");
    struct nlmsgerr *ack = NLMSG_DATA(header);
    if (ack->error) {
        errno = -ack->error;
        require(0, "guest route installation");
    }
    close(fd);
}

static void change_route(int family, const void *destination, unsigned char prefix, unsigned char type, int interface, int add) {
    struct route_message message = {
        .header.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
        .header.nlmsg_type = add ? RTM_NEWROUTE : RTM_DELROUTE,
        .body.route = {
            .rtm_family = (unsigned char)family,
            .rtm_dst_len = prefix,
            .rtm_table = RT_TABLE_MAIN,
            .rtm_protocol = RTPROT_STATIC,
            .rtm_scope = type == RTN_UNICAST ? RT_SCOPE_LINK : RT_SCOPE_UNIVERSE,
            .rtm_type = type,
        },
    };
    if (prefix)
        add_route_attribute(&message, RTA_DST, destination, family == AF_INET ? 4 : 16);
    if (interface)
        add_route_attribute(&message, RTA_OIF, &interface, sizeof(interface));
    submit_route_message(&message);
}

static void change_unreachable_rule(int family, const void *destination, int add) {
    struct route_message message = {
        .header.nlmsg_len = NLMSG_LENGTH(sizeof(struct fib_rule_hdr)),
        .header.nlmsg_type = add ? RTM_NEWRULE : RTM_DELRULE,
        .body.rule = {
            .family = (unsigned char)family,
            .dst_len = family == AF_INET ? 32 : 128,
            .action = FR_ACT_UNREACHABLE,
        },
    };
    unsigned int priority = 100;
    add_route_attribute(&message, FRA_DST, destination, family == AF_INET ? 4 : 16);
    add_route_attribute(&message, FRA_PRIORITY, &priority, sizeof(priority));
    submit_route_message(&message);
}

static void add_interface_address(int family, const char *text, int interface) {
    unsigned char address[16];
    require(inet_pton(family, text, address) == 1, "namespace interface address");
    struct route_message message = {
        .header.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg)),
        .header.nlmsg_type = RTM_NEWADDR,
        .body.address = {
            .ifa_family = (unsigned char)family,
            .ifa_prefixlen = family == AF_INET ? 24 : 64,
            .ifa_flags = IFA_F_NODAD,
            .ifa_index = (unsigned int)interface,
        },
    };
    add_route_attribute(&message, IFA_LOCAL, address, family == AF_INET ? 4 : 16);
    add_route_attribute(&message, IFA_ADDRESS, address, family == AF_INET ? 4 : 16);
    submit_route_message(&message);
}

static size_t begin_route_attribute(struct route_message *message, unsigned short type) {
    size_t offset = NLMSG_ALIGN(message->header.nlmsg_len);
    add_route_attribute(message, type | NLA_F_NESTED, "", 0);
    return offset;
}

static void end_route_attribute(struct route_message *message, size_t offset) {
    struct rtattr *attribute = (struct rtattr *)((unsigned char *)message + offset);
    attribute->rta_len = (unsigned short)(message->header.nlmsg_len - offset);
}

static void create_namespace_veth(pid_t child) {
    struct route_message peer = {
        .header.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
    };
    add_route_attribute(&peer, IFLA_IFNAME, "terra-inner", sizeof("terra-inner"));
    add_route_attribute(&peer, IFLA_NET_NS_PID, &child, sizeof(child));
    struct route_message message = {
        .header.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
        .header.nlmsg_type = RTM_NEWLINK,
    };
    add_route_attribute(&message, IFLA_IFNAME, "terra-outer", sizeof("terra-outer"));
    size_t link_info = begin_route_attribute(&message, IFLA_LINKINFO);
    add_route_attribute(&message, IFLA_INFO_KIND, "veth", sizeof("veth"));
    size_t link_data = begin_route_attribute(&message, IFLA_INFO_DATA);
    add_route_attribute(&message, VETH_INFO_PEER,
                        (unsigned char *)&peer + NLMSG_HDRLEN,
                        peer.header.nlmsg_len - NLMSG_HDRLEN);
    end_route_attribute(&message, link_data);
    end_route_attribute(&message, link_info);
    submit_route_message(&message);
}

static int configure_namespace_veth(const char *name, const char *address) {
    int control = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(control >= 0, "nested veth interface control");
    struct ifreq interface = {.ifr_flags = IFF_UP};
    strcpy(interface.ifr_name, name);
    require(ioctl(control, SIOCSIFFLAGS, &interface) == 0, "nested veth link enable");
    require(ioctl(control, SIOCGIFINDEX, &interface) == 0, "nested veth interface index");
    close(control);
    add_interface_address(AF_INET, address, interface.ifr_ifindex);
    return interface.ifr_ifindex;
}

static void exercise_nested_forwarding(const char *host, unsigned short port) {
    pid_t outer = fork();
    require(outer >= 0, "nested forwarding outer namespace process");
    if (outer == 0) {
        alarm(20);
        enter_network_namespace();
        struct sockaddr_in external = ipv4_address(host, port);
        struct timeval timeout = {.tv_sec = 2};
        int direct = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        require(direct >= 0 && setsockopt(direct, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
                "outer direct UDP receive bound");
        require(sendto(direct, "O", 1, 0, (struct sockaddr *)&external, sizeof(external)) == 1,
                "outer namespace authorized TSI send");
        char echo;
        require(recv(direct, &echo, 1, 0) == 1 && echo == 'O', "outer namespace authorized TSI echo");
        close(direct);
        int ready[2], configure[2];
        require(pipe(ready) == 0 && pipe(configure) == 0, "nested forwarding namespace synchronization");
        pid_t child = fork();
        require(child >= 0, "nested forwarding child");
        if (child == 0) {
            alarm(10);
            close(ready[0]);
            close(configure[1]);
            require(unshare(CLONE_NEWNET) == 0, "nested child network namespace");
            require(write(ready[1], "R", 1) == 1, "nested namespace ready");
            close(ready[1]);
            struct sockaddr_in gateway;
            require(read(configure[0], &gateway, sizeof(gateway)) == sizeof(gateway), "nested veth configured");
            close(configure[0]);
            int interface = configure_namespace_veth("terra-inner", "169.254.91.2");
            struct route_message route = {
                .header.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg)),
                .header.nlmsg_type = RTM_NEWROUTE,
                .body.route = {.rtm_family = AF_INET, .rtm_table = RT_TABLE_MAIN,
                               .rtm_protocol = RTPROT_STATIC, .rtm_type = RTN_UNICAST},
            };
            add_route_attribute(&route, RTA_GATEWAY, &gateway.sin_addr, sizeof(gateway.sin_addr));
            add_route_attribute(&route, RTA_OIF, &interface, sizeof(interface));
            submit_route_message(&route);
            int local = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
            require(local >= 0 && setsockopt(local, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
                    "nested native UDP receive bound");
            require(sendto(local, "L", 1, 0, (struct sockaddr *)&gateway, sizeof(gateway)) == 1 &&
                    recv(local, &echo, 1, 0) == 1 && echo == 'L', "nested veth native local echo");
            close(local);
            int forwarded = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
            require(forwarded >= 0 && setsockopt(forwarded, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
                    "nested forwarded UDP receive bound");
            static const char marker[] = "TERRA_NESTED_FORWARDING";
            require(connect(forwarded, (struct sockaddr *)&external, sizeof(external)) == 0 &&
                    send(forwarded, marker, sizeof(marker) - 1, 0) == sizeof(marker) - 1,
                    "nested external packet follows native gateway route");
            char reply[sizeof(marker)];
            require(recv(forwarded, reply, sizeof(reply), 0) < 0 &&
                    (errno == ENETUNREACH || errno == EHOSTUNREACH || errno == EAGAIN || errno == EWOULDBLOCK),
                    "kernel forwarding cannot obtain socket-offload external echo");
            close(forwarded);
            _exit(0);
        }
        close(ready[1]);
        close(configure[0]);
        require(read(ready[0], &echo, 1) == 1 && echo == 'R', "nested namespace setup rendezvous");
        close(ready[0]);
        create_namespace_veth(child);
        configure_namespace_veth("terra-outer", "169.254.91.1");
        write_mapping("/proc/sys/net/ipv4/ip_forward", "1\n");
        int local = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        struct sockaddr_in gateway = ipv4_address("169.254.91.1", 0);
        require(local >= 0 && bind(local, (struct sockaddr *)&gateway, sizeof(gateway)) == 0,
                "outer native veth echo endpoint");
        gateway.sin_port = htons(read_port(local));
        require(setsockopt(local, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
                "outer native veth echo receive bound");
        write_all(configure[1], (const unsigned char *)&gateway, sizeof(gateway));
        close(configure[1]);
        struct sockaddr_in source;
        socklen_t source_length = sizeof(source);
        require(recvfrom(local, &echo, 1, 0, (struct sockaddr *)&source, &source_length) == 1 && echo == 'L',
                "outer native veth receives child packet");
        require(sendto(local, &echo, 1, 0, (struct sockaddr *)&source, source_length) == 1,
                "outer native veth replies to child");
        close(local);
        int status;
        require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
                "nested forwarding stays native and bounded");
        _exit(0);
    }
    int status;
    require(waitpid(outer, &status, 0) == outer && WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "nested forwarding namespace regression");
    puts("SOCKET_NESTED_FORWARDING_UNSUPPORTED_OK");
}

static void exercise_connected_udp_route(const char *ip, unsigned short port) {
    pid_t child = fork();
    require(child >= 0, "connected UDP route namespace child");
    if (child == 0) {
        alarm(30);
        enter_network_namespace();
        int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        require(fd >= 0, "connected UDP route socket");
        struct timeval timeout = {.tv_sec = 10};
        require(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0, "connected UDP route send deadline");
        require(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "connected UDP route receive deadline");
        struct sockaddr_in peer = ipv4_address(ip, port);
        require(connect(fd, (struct sockaddr *)&peer, sizeof(peer)) == 0, "namespace connected UDP offload authorization");
        require(send(fd, "H", 1, 0) == 1, "namespace connected UDP offload send");
        char reply;
        require(recv(fd, &reply, 1, 0) == 1 && reply == 'H', "namespace connected UDP offload reply");
        int control = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        require(control >= 0, "connected UDP route interface socket");
        struct ifreq interface;
        memset(&interface, 0, sizeof(interface));
        strcpy(interface.ifr_name, "lo");
        require(ioctl(control, SIOCGIFINDEX, &interface) == 0, "connected UDP route loopback index");
        add_interface_address(AF_INET, ip, interface.ifr_ifindex);
        close(control);
        int local_server = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        require(local_server >= 0, "connected UDP route local server");
        require(setsockopt(local_server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "connected UDP route server deadline");
        require(bind(local_server, (struct sockaddr *)&peer, sizeof(peer)) == 0, "connected UDP route local peer bind");
        require(send(fd, "N", 1, 0) == 1, "connected UDP implicit destination follows new guest route");
        struct sockaddr_in source;
        socklen_t source_length = sizeof(source);
        require(recvfrom(local_server, &reply, 1, 0, (struct sockaddr *)&source, &source_length) == 1 && reply == 'N', "connected UDP native route delivery");
        require(sendto(local_server, "R", 1, 0, (struct sockaddr *)&source, source_length) == 1, "connected UDP native peer reply");
        require(recv(fd, &reply, 1, 0) == 1 && reply == 'R', "connected UDP native peer receive");
        struct sockaddr_in reported;
        socklen_t reported_length = sizeof(reported);
        require(getpeername(fd, (struct sockaddr *)&reported, &reported_length) == 0 && reported_length == sizeof(reported) && reported.sin_addr.s_addr == peer.sin_addr.s_addr && reported.sin_port == peer.sin_port, "connected UDP peer survives route change");
        require(shutdown(fd, SHUT_WR) == 0, "connected UDP write shutdown is logical");
        require(send(fd, "X", 1, MSG_NOSIGNAL) < 0 && errno == EPIPE, "connected UDP write shutdown prevents native routed send");
        usleep(100000);
        int error = 0;
        socklen_t error_length = sizeof(error);
        require(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_length) == 0 && error == 0, "UDP shutdown never sends invalid TCP FIN");
        close(local_server);
        close(fd);
        _exit(0);
    }
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "connected UDP route namespace status");
    puts("SOCKET_CONNECTED_ROUTE_OK");
}

static void expect_udp_route(const struct sockaddr *peer, socklen_t length, int expected_error, const char *label) {
    int fd = socket(peer->sa_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(fd >= 0, "route selection socket");
    errno = 0;
    int result = connect(fd, peer, length);
    require(expected_error ? result < 0 && errno == expected_error : result == 0, label);
    close(fd);
}

/* External UDP connect is guest-local; the broker's denial arrives as the asynchronous socket error. */
static void expect_udp_broker_denial(const struct sockaddr *peer, socklen_t length, const char *label) {
    int fd = socket(peer->sa_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(fd >= 0, "route selection socket");
    struct timeval timeout = {.tv_sec = 5};
    require(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "route selection receive deadline");
    require(connect(fd, peer, length) == 0 && send(fd, "R", 1, 0) == 1, label);
    char reply;
    errno = 0;
    require(recv(fd, &reply, 1, 0) < 0 && errno == EACCES, label);
    close(fd);
}

static void exercise_route_family(const struct sockaddr *peer, socklen_t length, const void *destination, int interface) {
    int family = peer->sa_family;
    if (family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&((const struct sockaddr_in6 *)peer)->sin6_addr))
        family = AF_INET;
    unsigned char prefix = family == AF_INET ? 32 : 128;
    expect_udp_broker_denial(peer, length, "missing route reaches denied broker capability");
    change_route(family, destination, prefix, RTN_UNREACHABLE, 0, 1);
    expect_udp_route(peer, length, EHOSTUNREACH, "guest unreachable route remains native");
    change_route(family, destination, prefix, RTN_UNREACHABLE, 0, 0);
    change_route(family, destination, prefix, RTN_BLACKHOLE, 0, 1);
    expect_udp_route(peer, length, EINVAL, "guest blackhole route remains native");
    change_route(family, destination, prefix, RTN_BLACKHOLE, 0, 0);
    change_route(family, destination, prefix, RTN_PROHIBIT, 0, 1);
    expect_udp_route(peer, length, EACCES, "guest prohibit route remains native");
    change_route(family, destination, prefix, RTN_PROHIBIT, 0, 0);
    change_route(family, destination, prefix, RTN_THROW, 0, 1);
    expect_udp_route(peer, length, ENETUNREACH, "guest throw route never falls through to broker");
    change_route(family, destination, prefix, RTN_THROW, 0, 0);
    change_unreachable_rule(family, destination, 1);
    expect_udp_route(peer, length, ENETUNREACH, "guest unreachable rule never falls through to broker");
    change_unreachable_rule(family, destination, 0);
    change_route(family, destination, prefix, RTN_UNICAST, interface, 1);
    expect_udp_route(peer, length, 0, "guest TUN route remains native");
    change_route(family, destination, prefix, RTN_UNICAST, interface, 0);
    change_route(family, destination, 0, RTN_UNICAST, interface, 1);
    expect_udp_route(peer, length, 0, "guest namespace default route remains native");
    change_route(family, destination, 0, RTN_UNICAST, interface, 0);
    expect_udp_broker_denial(peer, length, "removed default route restores broker classification");
}

static void exercise_route_constraints(struct sockaddr_in *peer, struct sockaddr_in6 *peer6, const char *interface_name) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(fd >= 0, "source-bound route socket");
    struct sockaddr_in source = ipv4_address("127.0.0.1", 0);
    require(bind(fd, (struct sockaddr *)&source, sizeof(source)) == 0, "explicit guest source bind");
    require(connect(fd, (struct sockaddr *)peer, sizeof(*peer)) < 0 && errno == EOPNOTSUPP, "absent route cannot reinterpret explicit guest source bind");
    close(fd);
    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(fd >= 0, "device-bound route socket");
    require(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name) + 1) == 0, "explicit guest device bind");
    require(connect(fd, (struct sockaddr *)peer, sizeof(*peer)) < 0 && errno == EOPNOTSUPP, "absent route cannot reinterpret device bind");
    close(fd);
    fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(fd >= 0, "IPv6 source-bound route socket");
    struct sockaddr_in6 source6 = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
    require(bind(fd, (struct sockaddr *)&source6, sizeof(source6)) == 0, "explicit guest IPv6 source bind");
    require(connect(fd, (struct sockaddr *)peer6, sizeof(*peer6)) < 0 && errno == EOPNOTSUPP, "absent IPv6 route cannot reinterpret source bind");
    close(fd);
    fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(fd >= 0, "IPv6 stream family validation socket");
    require(connect(fd, (struct sockaddr *)peer, sizeof(*peer)) < 0 && errno == EINVAL, "short IPv4 address on IPv6 TCP preserves native error");
    struct sockaddr_storage incompatible = {0};
    memcpy(&incompatible, peer, sizeof(*peer));
    require(connect(fd, (struct sockaddr *)&incompatible, sizeof(struct sockaddr_in6)) < 0 && errno == EAFNOSUPPORT, "IPv4 family on IPv6 TCP cannot offload");
    close(fd);
    struct sockaddr_in multicast = ipv4_address("239.1.2.3", 80);
    expect_udp_route((struct sockaddr *)&multicast, sizeof(multicast), EOPNOTSUPP, "unrouted multicast cannot offload");
    struct sockaddr_in broadcast = ipv4_address("255.255.255.255", 80);
    expect_udp_route((struct sockaddr *)&broadcast, sizeof(broadcast), EOPNOTSUPP, "unrouted broadcast cannot offload");
    struct sockaddr_in6 scoped = *peer6;
    scoped.sin6_scope_id = 12345;
    expect_udp_route((struct sockaddr *)&scoped, sizeof(scoped), EOPNOTSUPP, "external IPv6 scope cannot become host scope");
    scoped.sin6_scope_id = 0;
    require(inet_pton(AF_INET6, "fe80::90", &scoped.sin6_addr) == 1, "link-local route test address");
    expect_udp_route((struct sockaddr *)&scoped, sizeof(scoped), EINVAL, "unscoped link-local error remains native");
}

static void wait_for_native_route(const struct sockaddr *peer, socklen_t length, int expected_error, const char *label) {
    for (unsigned int attempt = 0; attempt < 5000; attempt++) {
        int fd = socket(peer->sa_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        require(fd >= 0, "carrier route selection socket");
        int result = connect(fd, peer, length);
        int route_error = result < 0 ? errno : 0;
        close(fd);
        errno = route_error;
        require(route_error == 0 || route_error == ENETUNREACH, label);
        if (route_error == expected_error)
            return;
        usleep(1000);
    }
    errno = ETIMEDOUT;
    require(0, label);
}

static void exercise_down_carrier(int tun, int interface, const char *name, struct sockaddr_in *peer, struct sockaddr_in6 *peer6) {
    char path[128];
    snprintf(path, sizeof(path), "/proc/sys/net/ipv4/conf/%s/ignore_routes_with_linkdown", name);
    write_mapping(path, "1\n");
    snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/ignore_routes_with_linkdown", name);
    write_mapping(path, "1\n");
    change_route(AF_INET, &peer->sin_addr, 32, RTN_UNICAST, interface, 1);
    change_route(AF_INET6, &peer6->sin6_addr, 128, RTN_UNICAST, interface, 1);
    int carrier = 0;
    require(ioctl(tun, TUNSETCARRIER, &carrier) == 0, "route matrix carrier disable");
    wait_for_native_route((struct sockaddr *)peer, sizeof(*peer), ENETUNREACH, "retained IPv4 route with down next hop remains native");
    wait_for_native_route((struct sockaddr *)peer6, sizeof(*peer6), ENETUNREACH, "retained IPv6 route with down next hop remains native");
    carrier = 1;
    require(ioctl(tun, TUNSETCARRIER, &carrier) == 0, "route matrix carrier restore");
    wait_for_native_route((struct sockaddr *)peer, sizeof(*peer), 0, "restored IPv4 next hop remains native");
    wait_for_native_route((struct sockaddr *)peer6, sizeof(*peer6), 0, "restored IPv6 next hop remains native");
    change_route(AF_INET, &peer->sin_addr, 32, RTN_UNICAST, interface, 0);
    change_route(AF_INET6, &peer6->sin6_addr, 128, RTN_UNICAST, interface, 0);
}

static void exercise_denied_to_native(struct sockaddr_in *denied) {
    struct sockaddr_in local = ipv4_address("127.0.0.1", 0);
    int listener = create_listener((struct sockaddr *)&local, sizeof(local));
    local.sin_port = htons(read_port(listener));
    for (unsigned int nonblocking = 0; nonblocking < 2; nonblocking++) {
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        require(fd >= 0, "failed external connect retry socket");
        require(connect(fd, (struct sockaddr *)denied, sizeof(*denied)) < 0 && errno == EACCES, "external TCP connect denied before native retry");
        if (nonblocking)
            require(fcntl(fd, F_SETFL, O_NONBLOCK) == 0, "nonblocking native reconnect");
        int connected = connect(fd, (struct sockaddr *)&local, sizeof(local));
        require(connected == 0 || (nonblocking && connected < 0 && errno == EINPROGRESS), "same socket reconnects natively after external denial");
        if (connected != 0) {
            int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
            require(epoll_fd >= 0, "native reconnect readiness descriptor");
            struct epoll_event ready = {.events = EPOLLOUT, .data.fd = fd};
            require(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ready) == 0, "register native reconnect readiness");
            require(epoll_wait(epoll_fd, &ready, 1, WAIT_MS) == 1, "native reconnect completes through readiness");
            close(epoll_fd);
        }
        int error;
        socklen_t error_length = sizeof(error);
        require(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_length) == 0 && error == 0, "native reconnect retires external error state");
        require(fcntl(fd, F_SETFL, 0) == 0, "blocking native retry data exchange");
        int accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
        require(accepted >= 0, "native retry listener accepts");
        require(write(fd, "N", 1) == 1, "native retry client write");
        char byte;
        require(read(accepted, &byte, 1) == 1 && byte == 'N', "native retry server receives");
        require(write(accepted, "R", 1) == 1, "native retry server write");
        require(read(fd, &byte, 1) == 1 && byte == 'R', "native retry client receives");
        close(accepted);
        close(fd);
    }
    close(listener);
}

static void exercise_routes(void) {
    pid_t child = fork();
    require(child >= 0, "route namespace child");
    if (child == 0) {
        enter_network_namespace();
        int tun = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
        require(tun >= 0, "route matrix TUN descriptor");
        struct ifreq interface = {.ifr_flags = IFF_TUN | IFF_NO_PI};
        require(ioctl(tun, TUNSETIFF, &interface) == 0, "route matrix TUN interface");
        int control = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        require(control >= 0, "route matrix interface control");
        struct ifreq interface_index = interface;
        require(ioctl(control, SIOCGIFINDEX, &interface_index) == 0, "route matrix interface index");
        interface.ifr_flags = IFF_UP;
        require(ioctl(control, SIOCSIFFLAGS, &interface) == 0, "route matrix interface enable");
        close(control);
        add_interface_address(AF_INET, "169.254.90.1", interface_index.ifr_ifindex);
        add_interface_address(AF_INET6, "fd00:90::1", interface_index.ifr_ifindex);
        struct sockaddr_in peer = ipv4_address("192.0.2.90", 80);
        struct sockaddr_in6 peer6 = {.sin6_family = AF_INET6, .sin6_port = htons(80)};
        require(inet_pton(AF_INET6, "2001:db8::90", &peer6.sin6_addr) == 1, "IPv6 route matrix address");
        exercise_route_family((struct sockaddr *)&peer, sizeof(peer), &peer.sin_addr, interface_index.ifr_ifindex);
        exercise_route_family((struct sockaddr *)&peer6, sizeof(peer6), &peer6.sin6_addr, interface_index.ifr_ifindex);
        struct sockaddr_in6 mapped = {.sin6_family = AF_INET6, .sin6_port = htons(80)};
        require(inet_pton(AF_INET6, "::ffff:192.0.2.90", &mapped.sin6_addr) == 1, "mapped route matrix address");
        exercise_route_family((struct sockaddr *)&mapped, sizeof(mapped), &peer.sin_addr, interface_index.ifr_ifindex);
        exercise_route_constraints(&peer, &peer6, interface.ifr_name);
        exercise_down_carrier(tun, interface_index.ifr_ifindex, interface.ifr_name, &peer, &peer6);
        exercise_denied_to_native(&peer);
        close(tun);
        _exit(0);
    }
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "guest FIB route matrix status");
    puts("SOCKET_ROUTES_OK");
}

static unsigned short parse_port(const char *text) {
    char *end;
    unsigned long port = strtoul(text, &end, 10);
    require(*text && !*end && port > 0 && port <= 65535, "external endpoint port");
    return (unsigned short)port;
}

static int read_send_limit(int fd) {
    int bytes = 0;
    socklen_t length = sizeof(bytes);
    require(getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bytes, &length) == 0 &&
            length == sizeof(bytes), "read effective send limit");
    return bytes;
}

static void set_tcp_write_memory(int minimum, int initial, int maximum) {
    FILE *setting = fopen("/proc/sys/net/ipv4/tcp_wmem", "w");
    require(setting != NULL, "open TCP write memory setting");
    require(fprintf(setting, "%d %d %d\n", minimum, initial, maximum) > 0,
            "set TCP write memory limits");
    require(fclose(setting) == 0, "flush TCP write memory setting");
}

static int connect_with_send_limit(const struct sockaddr_in *peer, int requested) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(fd >= 0, "send limit TCP socket");
    struct timeval timeout = {.tv_sec = 10};
    require(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0 &&
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
            "bounded send limit connect and receive");
    if (requested)
        require(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &requested, sizeof(requested)) == 0,
                "explicit send limit before connect");
    int before = read_send_limit(fd);
    require(connect(fd, (const struct sockaddr *)peer, sizeof(*peer)) == 0,
            "send limit external connect");
    printf("SOCKET_SEND_LIMIT_CONNECT before=%d after=%d explicit=%d\n",
           before, read_send_limit(fd), requested);
    fflush(stdout);
    require(read_send_limit(fd) == before,
            "successful external TCP preserves the native send limit");
    return fd;
}

static void exercise_send_limits(const char *host, unsigned short port,
                                 unsigned short refused_port) {
    FILE *setting = fopen("/proc/sys/net/ipv4/tcp_wmem", "r");
    int original[3];
    require(setting != NULL && fscanf(setting, "%d %d %d", &original[0], &original[1],
                                      &original[2]) == 3, "read TCP write memory limits");
    require(fclose(setting) == 0, "close TCP write memory setting");
    struct sockaddr_in peer = ipv4_address(host, port);
    set_tcp_write_memory(4096, 16384, 262144);
    close(connect_with_send_limit(&peer, 0));
    close(connect_with_send_limit(&peer, 1024));
    close(connect_with_send_limit(&peer, 65536));
    set_tcp_write_memory(4096, 16384, 24576);
    close(connect_with_send_limit(&peer, 0));
    set_tcp_write_memory(4096, 65536, 262144);
    close(connect_with_send_limit(&peer, 0));

    struct sockaddr_in local = ipv4_address("127.0.0.1", 0);
    int listener = create_listener((struct sockaddr *)&local, sizeof(local));
    local.sin_port = htons(read_port(listener));
    int local_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(local_fd >= 0, "native local send limit socket");
    int local_before = read_send_limit(local_fd);
    require(connect(local_fd, (struct sockaddr *)&local, sizeof(local)) == 0 &&
            read_send_limit(local_fd) >= local_before, "native local default never contracts");
    int accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    require(accepted >= 0, "native local send limit accept");
    close(accepted);
    close(local_fd);
    close(listener);
    set_tcp_write_memory(4096, 16384, 262144);
    int udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(udp >= 0, "UDP send limit socket");
    int udp_before = read_send_limit(udp);
    require(connect(udp, (struct sockaddr *)&peer, sizeof(peer)) == 0 &&
            read_send_limit(udp) == udp_before, "external UDP send limit unchanged");
    close(udp);
    int refused = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(refused >= 0, "refused external send limit socket");
    int refused_before = read_send_limit(refused);
    struct sockaddr_in unavailable = ipv4_address(host, refused_port);
    require(connect(refused, (struct sockaddr *)&unavailable, sizeof(unavailable)) == -1 &&
            errno == ECONNREFUSED && read_send_limit(refused) == refused_before,
            "failed external connect leaves default send limit unchanged");
    close(refused);

    int fd = connect_with_send_limit(&peer, 0);
    int previous_send_limit = read_send_limit(fd);
    struct timespec ready_started, ready_now;
    require(clock_gettime(CLOCK_MONOTONIC, &ready_started) == 0, "paused peer wait start");
    while (access("/work/SEND_LIMIT_PEER_READY", F_OK) != 0) {
        require(clock_gettime(CLOCK_MONOTONIC, &ready_now) == 0 &&
                ready_now.tv_sec - ready_started.tv_sec < 10, "paused peer readiness deadline");
        usleep(1000);
    }
    enum { PREFIX_BOUND = 16 * 1024 * 1024 };
    unsigned char *bytes = malloc(PREFIX_BOUND);
    require(bytes != NULL, "queued prefix allocation");
    for (size_t index = 0; index < PREFIX_BOUND; index++)
        bytes[index] = (unsigned char)(index % 251);
    size_t sent = 0;
    int stalled_ms = 0;
    while (stalled_ms < 250) {
        require(sent < PREFIX_BOUND, "paused peer bounds accepted prefix");
        ssize_t count = send(fd, bytes + sent, PREFIX_BOUND - sent,
                             MSG_DONTWAIT | MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            usleep(10000);
            stalled_ms += 10;
            continue;
        }
        require(count > 0, "queued prefix acceptance");
        sent += (size_t)count;
        stalled_ms = 0;
    }
    require(sent > (size_t)previous_send_limit,
            "accepted prefix exceeds the socket send limit");
    int requested = 1024;
    require(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &requested, sizeof(requested)) == 0 &&
            read_send_limit(fd) < previous_send_limit, "later explicit shrink takes effect");
    require(shutdown(fd, SHUT_WR) == 0, "queued prefix FIN after shrink");
    FILE *release = fopen("/work/SEND_LIMIT_SHRINK_READY", "w");
    require(release != NULL && fprintf(release, "%zu\n", sent) > 0,
            "release paused peer with accepted prefix length");
    require(fclose(release) == 0, "flush paused peer release");
    size_t received = 0;
    unsigned char reply[8192];
    ssize_t count;
    while ((count = recv(fd, reply, sizeof(reply), 0)) > 0) {
        require((size_t)count <= sent - received &&
                memcmp(reply, bytes + received, (size_t)count) == 0,
                "accepted prefix integrity after send limit shrink");
        received += (size_t)count;
    }
    require(count == 0 && received == sent, "exact accepted prefix precedes EOF after shrink");
    printf("SOCKET_SEND_LIMIT_SHRINK_OK accepted=%zu echoed=%zu effective=%d stable_window_ms=250\n",
           sent, received, read_send_limit(fd));
    close(fd);
    free(bytes);
    set_tcp_write_memory(original[0], original[1], original[2]);
    puts("SOCKET_SEND_LIMITS_OK");
}

static void exercise_dns(unsigned int expected_count) {
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM};
    struct addrinfo *addresses = NULL;
    int error = getaddrinfo("many.test", "80", &hints, &addresses);
    if (error)
        fprintf(stderr, "resolver: %s\n", gai_strerror(error));
    require(error == 0, "static libc DNS resolution");
    unsigned int seen = 0;
    for (struct addrinfo *entry = addresses; entry; entry = entry->ai_next) {
        require(entry->ai_family == AF_INET && entry->ai_addrlen == sizeof(struct sockaddr_in), "resolved address family");
        const struct sockaddr_in *address = (const void *)entry->ai_addr;
        unsigned int ip = ntohl(address->sin_addr.s_addr);
        unsigned int last = ip & 255;
        require((ip >> 8) == 0xc00002 && last >= 1 && last <= 32, "resolved address range");
        require(ntohs(address->sin_port) == 80, "resolved service port");
        seen |= 1U << (last - 1);
    }
    freeaddrinfo(addresses);
    require(seen == (expected_count == 32 ? 0xffffffffU : 1U), "all expected DNS answers received");
    puts("SOCKET_DNS_OK");
}

static void exercise_reset_after_fin(const char *ip, unsigned short port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(fd >= 0, "TCP reset after FIN socket");
    struct timeval timeout = {.tv_sec = 10};
    require(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0,
            "TCP reset after FIN deadlines");
    struct sockaddr_in peer = ipv4_address(ip, port);
    require(connect(fd, (struct sockaddr *)&peer, sizeof(peer)) == 0, "TCP reset after FIN connect");
    char byte;
    require(recv(fd, &byte, 1, 0) == 0, "remote FIN exposes EOF while guest write half stays open");
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    require(epoll_fd >= 0, "TCP reset after FIN readiness descriptor");
    struct epoll_event ready = {.events = EPOLLERR, .data.fd = fd};
    require(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ready) == 0, "register TCP reset after FIN readiness");
    require(send(fd, "R", 1, MSG_NOSIGNAL) == 1, "remote FIN leaves guest write half open for reset synchronization");
    require(epoll_wait(epoll_fd, &ready, 1, WAIT_MS) == 1 && (ready.events & EPOLLERR), "reset after remote FIN becomes error ready");
    int error;
    socklen_t error_length = sizeof(error);
    require(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_length) == 0 && error == ECONNRESET, "reset after remote FIN reports ECONNRESET");
    require(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_length) == 0 && error == 0, "TCP reset error consumed exactly once");
    require(recv(fd, &byte, 1, MSG_DONTWAIT) == 0, "completed receive half remains EOF after reset error consumption");
    close(epoll_fd);
    close(fd);
    puts("SOCKET_RESET_AFTER_FIN_OK");
}

static void serve_published_udp(unsigned short port, int loopback_only) {
    alarm(0);
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(fd >= 0, "published UDP guest service");
    struct sockaddr_in local = ipv4_address(loopback_only ? "127.0.0.1" : "0.0.0.0", port);
    require(bind(fd, (struct sockaddr *)&local, sizeof(local)) == 0, "published UDP guest bind");
    struct in_addr relay;
    require(inet_pton(AF_INET, "169.254.96.1", &relay) == 1, "published UDP relay address");
    trace_phase("UDP_PUBLISHED_READY");
    for (;;) {
        unsigned char bytes[4097];
        struct sockaddr_in peer;
        socklen_t peer_length = sizeof(peer);
        ssize_t length = recvfrom(fd, bytes, sizeof(bytes), 0, (struct sockaddr *)&peer, &peer_length);
        if (length < 0 && errno == EINTR)
            continue;
        require(length >= 0 && length <= 4096, "published UDP preserves the datagram bound");
        require(peer_length == sizeof(peer) && peer.sin_family == AF_INET &&
                peer.sin_addr.s_addr == relay.s_addr && peer.sin_port != 0,
                "published UDP preserves relay source identity");
        printf("UDP_PUBLISHED_PEER_OK port=%u length=%zd\n", ntohs(peer.sin_port), length);
        fflush(stdout);
        require(sendto(fd, bytes, (size_t)length, 0, (struct sockaddr *)&peer, peer_length) == length,
                "published UDP echoes binary and empty datagrams");
    }
}

int main(int argc, char **argv) {
    alarm(90);
    signal(SIGPIPE, SIG_IGN);
    if (argc == 4 && strcmp(argv[1], "--reset-after-fin") == 0) {
        exercise_reset_after_fin(argv[2], parse_port(argv[3]));
        return 0;
    }
    if (argc == 3 && (strcmp(argv[1], "--published-udp") == 0 || strcmp(argv[1], "--published-udp-loopback") == 0)) {
        serve_published_udp(parse_port(argv[2]), strcmp(argv[1], "--published-udp-loopback") == 0);
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "--udp-error-budget") == 0) {
        exercise_udp_error_budget(argv[2], parse_port(argv[3]));
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "--quic-socket") == 0) {
        exercise_quic_socket(argv[2], parse_port(argv[3]));
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "--quic-credit") == 0) {
        exercise_quic_credit(argv[2], parse_port(argv[3]));
        return 0;
    }
    exercise_local();
    if (argc == 1 || (argc == 2 && strcmp(argv[1], "local") == 0))
        return 0;
    if (argc == 2 && strcmp(argv[1], "--namespaces") == 0) {
        exercise_namespaces();
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--routes") == 0) {
        exercise_routes();
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--errors") == 0) {
        exercise_errors();
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--dns") == 0) {
        exercise_dns(1);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--dns-tcp-fallback") == 0) {
        exercise_dns(32);
        return 0;
    }
    if (argc == 5 && strcmp(argv[1], "--send-limits") == 0) {
        exercise_send_limits(argv[2], parse_port(argv[3]), parse_port(argv[4]));
        return 0;
    }
    require(argc == 6 && strcmp(argv[1], "--external") == 0, "usage: [local | --namespaces | --routes | --errors | --dns | --dns-tcp-fallback | --quic-socket IPV4 UDP_PORT | --quic-credit IPV4 UDP_PORT | --send-limits IPV4 TCP_PORT REFUSED_PORT | --external IPV4 TCP_PORT UDP_PORT_1 UDP_PORT_2]");
    struct sockaddr_in peer = ipv4_address(argv[2], parse_port(argv[3]));
    exercise_tcp((struct sockaddr *)&peer, sizeof(peer));
    trace_phase("SOCKET_TCP_PEEK_OFFSET_POST_CONNECT");
    exercise_tcp_peek_offset((struct sockaddr *)&peer, sizeof(peer), 0);
    trace_phase("SOCKET_TCP_PEEK_OFFSET_PRE_CONNECT");
    exercise_tcp_peek_offset((struct sockaddr *)&peer, sizeof(peer), 1);
    puts("SOCKET_TCP_PEEK_OFFSET_OK");
    exercise_concurrent_tcp((struct sockaddr *)&peer, sizeof(peer));
    exercise_udp(argv[2], parse_port(argv[4]), parse_port(argv[5]));
    exercise_udp_native_first(argv[2], parse_port(argv[4]));
    exercise_udp_receive_budget(argv[2], parse_port(argv[4]));
    exercise_ipv6_udp_disconnect(argv[2], parse_port(argv[4]), 1);
    exercise_ipv6_udp_disconnect("fd53:4d00::1", parse_port(argv[4]), 0);
    exercise_connected_udp_route(argv[2], parse_port(argv[4]));
    exercise_nested_forwarding(argv[2], parse_port(argv[4]));
    puts("SOCKET_EXTERNAL_OK");
    return 0;
}
