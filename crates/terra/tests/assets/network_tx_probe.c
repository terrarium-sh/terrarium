#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define IDLE_SOCKETS 40
#define WAIT_MS 10000

static void require(int condition, const char *what) {
    if (!condition) {
        fprintf(stderr, "FAIL %s: errno=%d (%s)\n", what, errno, strerror(errno));
        exit(1);
    }
}

static void wait_ready(int descriptor, short events, const char *what) {
    struct pollfd waiter = {.fd = descriptor, .events = events};
    int count;
    do {
        count = poll(&waiter, 1, WAIT_MS);
    } while (count < 0 && errno == EINTR);
    require(count == 1 && (waiter.revents & events) &&
            !(waiter.revents & (POLLERR | POLLHUP | POLLNVAL)), what);
}

static void exercise_sockets(unsigned short port) {
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons(port)};
    require(inet_pton(AF_INET, "100.96.0.1", &peer.sin_addr) == 1, "host service address");
    int sockets[IDLE_SOCKETS];
    for (unsigned int index = 0; index < IDLE_SOCKETS; index++) {
        sockets[index] = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        require(sockets[index] >= 0, "idle TCP socket");
        require(connect(sockets[index], (void *)&peer, sizeof(peer)) == 0, "idle TCP connect");
        uint8_t byte;
        require(recv(sockets[index], &byte, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN,
                "idle TCP Read stays pending without peer data");
    }
    printf("NETWORK_TX_IDLE_READS count=%d\n", IDLE_SOCKETS);
    fflush(stdout);
    require(close(sockets[0]) == 0, "independent idle TCP close");
    int active = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(active >= 0, "active TCP socket");
    require(connect(active, (void *)&peer, sizeof(peer)) == 0, "active TCP connect after idle reads");
    uint8_t byte = 0x5a;
    require(send(active, &byte, 1, MSG_NOSIGNAL) == 1, "active TCP send after idle reads");
    wait_ready(active, POLLIN, "active TCP response after idle close");
    require(recv(active, &byte, 1, 0) == 1 && byte == 0xa5,
            "host observed idle close before responding");
    require(close(active) == 0, "active TCP close");
    for (unsigned int index = 1; index < IDLE_SOCKETS; index++)
        require(close(sockets[index]) == 0, "idle TCP cleanup");
    puts("NETWORK_TX_IDLE_READS_OK");
}

int main(int argc, char **argv) {
    alarm(60);
    signal(SIGPIPE, SIG_IGN);
    require(argc == 3 && strcmp(argv[1], "sockets") == 0, "usage: sockets PORT");
    char *end;
    unsigned long port = strtoul(argv[2], &end, 10);
    require(*argv[2] && !*end && port && port <= 65535, "authorized host port");
    exercise_sockets((unsigned short)port);
    return 0;
}
