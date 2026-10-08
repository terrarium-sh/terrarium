#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static void require(int condition, const char *what) {
    if (!condition) {
        perror(what);
        exit(1);
    }
}

static struct sockaddr_un unix_address(const char *path) {
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    struct stat metadata;
    require(stat(path, &metadata) == 0 && S_ISSOCK(metadata.st_mode), "mounted host Unix socket path");
    require(strlen(path) < sizeof(address.sun_path), "Unix socket path length");
    memcpy(address.sun_path, path, strlen(path) + 1);
    return address;
}

/* The broker shares the host network namespace, so it must not create Unix sockets at all. */
static int create_unix_socket(int worker, int type) {
    int fd = socket(AF_UNIX, type | SOCK_CLOEXEC, 0);
    if (worker)
        require(fd >= 0, "create VM Unix socket");
    else
        require(fd < 0 && errno == EPERM, "broker Unix socket boundary");
    return fd;
}

static void probe_unix_stream(int worker, const char *path) {
    struct sockaddr_un address = unix_address(path);
    int fd = create_unix_socket(worker, SOCK_STREAM);
    if (fd < 0)
        return;
    int connected = connect(fd, (struct sockaddr *)&address, sizeof(address));
    require(connected < 0 && errno == EPERM, "mounted Unix stream socket boundary");
    close(fd);
}

static void probe_unix_datagram(int worker, const char *path) {
    struct sockaddr_un address = unix_address(path);
    int fd = create_unix_socket(worker, SOCK_DGRAM);
    if (fd < 0)
        return;
    ssize_t sent = sendto(fd, "D", 1, 0, (struct sockaddr *)&address, sizeof(address));
    require(sent < 0 && errno == EPERM, "mounted Unix datagram socket boundary");
    char byte = 'M';
    struct iovec data = {.iov_base = &byte, .iov_len = 1};
    struct msghdr message = {
        .msg_name = &address,
        .msg_namelen = sizeof(address),
        .msg_iov = &data,
        .msg_iovlen = 1,
    };
    sent = sendmsg(fd, &message, 0);
    require(sent < 0 && errno == EPERM, "addressed Unix sendmsg boundary");
    close(fd);
}

int main(int argc, char **argv) {
    require(argc == 6, "expected role, port, KVM availability, host Unix stream and datagram paths");
    for (int inherited = 3; inherited < 256; inherited++) {
        if (inherited != 7)
            require(fcntl(inherited, F_GETFD) < 0 && errno == EBADF, "unrelated inherited descriptor");
    }
    require(prctl(PR_SET_PDEATHSIG, 0, 0, 0, 0) < 0 && errno == EPERM, "immutable parent-death signal");
    require(setsid() < 0 && errno == EPERM, "worker session confinement");
    require(setpgid(0, 0) < 0 && errno == EPERM, "worker process-group confinement");
    int worker = strcmp(argv[1], "vm") == 0;
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons((unsigned short)atoi(argv[2])),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        require(worker && (errno == EPERM || errno == EACCES), "native network socket boundary");
    } else {
        int connected = connect(fd, (struct sockaddr *)&address, sizeof(address));
        require(worker ? connected < 0 : connected == 0, "network namespace boundary");
        if (!worker)
            require(write(fd, "N", 1) == 1, "network peer output");
        close(fd);
    }
    probe_unix_stream(worker, argv[4]);
    probe_unix_datagram(worker, argv[5]);
    if (worker && atoi(argv[3])) {
        int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
        require(kvm >= 0, "KVM grant");
        require(ioctl(kvm, KVM_GET_API_VERSION, 0) == KVM_API_VERSION, "KVM API");
        int vm = ioctl(kvm, KVM_CREATE_VM, 0);
        require(vm >= 0, "create VM");
        int cpu = ioctl(vm, KVM_CREATE_VCPU, 0);
        require(cpu >= 0, "create vCPU");
        close(cpu);
        close(vm);
        close(kvm);
    } else if (!worker) {
        require(open("/dev/kvm", O_RDWR) < 0, "broker has no KVM grant");
    }
    char byte = worker ? 'V' : 'B';
    require(write(7, &byte, 1) == 1, "inherited IPC output");
    require(read(7, &byte, 1) == 0, "IPC EOF");
    return 0;
}
