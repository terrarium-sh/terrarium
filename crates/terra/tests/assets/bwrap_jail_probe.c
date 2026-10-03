#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static void fail(const char *what) {
    perror(what);
    exit(1);
}

static void must_be_hidden(const char *path) {
    errno = 0;
    int fd = open(path, O_RDONLY);
    if (fd >= 0 || errno != ENOENT) {
        fprintf(stderr, "host path is visible: %s (errno %d)\n", path, errno);
        exit(1);
    }
}

static void must_be_readonly(const char *path) {
    char byte;
    int fd = open(path, O_RDONLY);
    if (fd < 0 || read(fd, &byte, 1) != 1)
        fail("reading an approved file");
    close(fd);

    fd = open(path, O_WRONLY | O_TRUNC);
    if (fd >= 0) {
        close(fd);
        fprintf(stderr, "wrote protected file: %s\n", path);
        exit(1);
    }
    if (unlink(path) == 0) {
        fprintf(stderr, "unlinked protected file: %s\n", path);
        exit(1);
    }
}

int main(int argc, char **argv) {
    if (argc >= 3 && strcmp(argv[1], "__vm") == 0) {
        argv[2] = argv[0];
        argv += 2;
        argc -= 2;
    }
    if (argc == 2 && strcmp(argv[1], "seccomp-child") == 0) {
        syscall(SYS_getpid);
        fprintf(stderr, "seccomp allowed getpid after exec\n");
        return 1;
    }
    if (argc != 8) {
        fprintf(stderr, "expected sentinel, other box, share, recipe, pin, host pid, port\n");
        return 1;
    }

    must_be_hidden(argv[1]);
    must_be_hidden(argv[2]);
    must_be_readonly(argv[3]);
    must_be_readonly(argv[4]);
    must_be_readonly(argv[5]);
    must_be_readonly(argv[6]);

    int socket_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (socket_fd < 0)
        fail("creating native socket");
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons((unsigned short)atoi(argv[7])),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
        fail("native socket reaching host loopback");
    if (write(socket_fd, "N", 1) != 1)
        fail("native socket sending to host loopback");
    close(socket_fd);
    puts("JAIL_PROBES_OK");
    fflush(stdout);

    char *child_argv[] = {argv[0], "seccomp-child", NULL};
    execv(argv[0], child_argv);
    fail("executing probe under inherited seccomp filter");
}
