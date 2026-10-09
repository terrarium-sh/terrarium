#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/vm_sockets.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

#define HOST_CID 2
#define GUEST_CID 3
#define AGENT_PORT 6000
#define CONTROL_PORT 6001
#define TCP_PORT 6002
#define UDP_PORT 6003

static void require(int condition, const char *operation) {
    if (!condition) {
        fprintf(stderr, "FAIL %s: errno=%d (%s)\n", operation, errno, strerror(errno));
        exit(1);
    }
}

static void write_marker(const char *path, long first, long second) {
    int marker = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    require(marker >= 0, "open marker");
    require(dprintf(marker, "%ld %ld\n", first, second) > 0, "write marker");
    require(fsync(marker) == 0, "flush marker");
    require(close(marker) == 0, "close marker");
}

static void find_vsock_device(char *path, size_t capacity) {
    DIR *devices = opendir("/sys/bus/virtio/devices");
    require(devices != NULL, "inspect virtio devices");
    struct dirent *entry;
    unsigned int count = 0;
    while ((entry = readdir(devices)) != NULL) {
        char device[512];
        int length = snprintf(device, sizeof(device), "/sys/bus/virtio/devices/%s/device", entry->d_name);
        require(length > 0 && (size_t)length < sizeof(device), "virtio device path bound");
        FILE *file = fopen(device, "r");
        if (!file)
            continue;
        unsigned int id = 0;
        int parsed = fscanf(file, "%x", &id);
        require(fclose(file) == 0, "close virtio device identity");
        if (parsed != 1 || id != 19)
            continue;
        count++;
        length = snprintf(path, capacity, "/sys/bus/virtio/devices/%s", entry->d_name);
        require(length > 0 && (size_t)length < capacity, "vsock device path bound");
    }
    require(closedir(devices) == 0, "close virtio device directory");
    require(count == 1, "one stock virtio-vsock device");
}

/* Duplicate the agent's established vsock descriptor bound to one fixed guest port. */
static int duplicate_agent_vsock(unsigned int port) {
    DIR *descriptors = opendir("/proc/1/fd");
    require(descriptors != NULL, "inspect agent descriptors");
    int process = (int)syscall(SYS_pidfd_open, 1, 0);
    require(process >= 0, "open agent pidfd");
    int agent = -1;
    unsigned int count = 0;
    struct dirent *entry;
    while ((entry = readdir(descriptors)) != NULL) {
        char *end;
        long number = strtol(entry->d_name, &end, 10);
        if (!*entry->d_name || *end || number < 0 || number > INT32_MAX)
            continue;
        int descriptor = (int)syscall(SYS_pidfd_getfd, process, (int)number, 0);
        if (descriptor < 0)
            continue;
        struct sockaddr_vm local = {0}, peer = {0};
        socklen_t length = sizeof(local);
        if (getsockname(descriptor, (void *)&local, &length) == 0 &&
            local.svm_family == AF_VSOCK && local.svm_port == port) {
            require(length == sizeof(local) && local.svm_cid == GUEST_CID, "fixed guest endpoint");
            length = sizeof(peer);
            require(getpeername(descriptor, (void *)&peer, &length) == 0 &&
                    length == sizeof(peer) && peer.svm_family == AF_VSOCK &&
                    peer.svm_cid == HOST_CID && peer.svm_port == port,
                    "fixed host endpoint");
            require(agent < 0, "one guest agent vsock descriptor");
            agent = descriptor;
            count++;
        } else {
            close(descriptor);
        }
    }
    require(closedir(descriptors) == 0 && close(process) == 0, "close agent descriptor inspection");
    require(count == 1, "one established connection per fixed endpoint");
    return agent;
}

static void reject_endpoint(unsigned int guest_port, unsigned int host_port) {
    int descriptor = socket(AF_VSOCK, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    require(descriptor >= 0, "create rejected vsock probe");
    struct sockaddr_vm local = {.svm_family = AF_VSOCK, .svm_cid = GUEST_CID, .svm_port = guest_port};
    require(bind(descriptor, (void *)&local, sizeof(local)) == 0, "bind unknown guest endpoint");
    struct sockaddr_vm peer = {.svm_family = AF_VSOCK, .svm_cid = HOST_CID, .svm_port = host_port};
    int connected = connect(descriptor, (void *)&peer, sizeof(peer));
    require(connected == -1, "unknown endpoint never establishes immediately");
    if (errno == EINPROGRESS) {
        struct pollfd ready = {.fd = descriptor, .events = POLLOUT};
        require(poll(&ready, 1, 3000) == 1, "unknown endpoint rejection is bounded");
        int error = 0;
        socklen_t length = sizeof(error);
        require(getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error != 0,
                "unknown endpoint completion is rejected");
    } else {
        require(errno == ECONNREFUSED || errno == ECONNRESET || errno == EINVAL || errno == EHOSTUNREACH,
                "unknown endpoint rejection error");
    }
    require(close(descriptor) == 0, "close rejected endpoint");
}

/* A cross-role opening returns a protocol refusal or reset, followed by no service bytes. */
static void reject_opening(unsigned int guest_port, unsigned int host_port, unsigned char opcode) {
    int descriptor = socket(AF_VSOCK, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    require(descriptor >= 0, "create opening probe");
    uint64_t buffer = 32768;
    require(setsockopt(descriptor, AF_VSOCK, SO_VM_SOCKETS_BUFFER_MAX_SIZE,
                       &buffer, sizeof(buffer)) == 0 &&
            setsockopt(descriptor, AF_VSOCK, SO_VM_SOCKETS_BUFFER_SIZE,
                       &buffer, sizeof(buffer)) == 0, "bounded opening vsock buffer");
    struct sockaddr_vm local = {.svm_family = AF_VSOCK, .svm_cid = GUEST_CID, .svm_port = guest_port};
    require(bind(descriptor, (void *)&local, sizeof(local)) == 0, "bind flow source endpoint");
    struct sockaddr_vm peer = {.svm_family = AF_VSOCK, .svm_cid = HOST_CID, .svm_port = host_port};
    int connected = connect(descriptor, (void *)&peer, sizeof(peer));
    require(connected == 0 || errno == EINPROGRESS, "flow endpoint class admits transport");
    if (connected != 0) {
        struct pollfd ready = {.fd = descriptor, .events = POLLOUT};
        require(poll(&ready, 1, 3000) == 1, "flow transport opening is bounded");
        int error = 0;
        socklen_t length = sizeof(error);
        require(getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0,
                "flow transport connects before application authorization");
    }
    int flags = fcntl(descriptor, F_GETFL);
    require(flags >= 0 && fcntl(descriptor, F_SETFL, flags & ~O_NONBLOCK) == 0,
            "blocking opening probe");
    struct timeval timeout = {.tv_sec = 3};
    require(setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
            setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0,
            "bounded application opening");
    unsigned char opening[12] = {opcode, 0, 0, 0, 4, 0, 0, 0, TERRA_NETWORK_ABI, 0, 0, 0};
    require(send(descriptor, opening, sizeof(opening), MSG_NOSIGNAL) == sizeof(opening),
            "send cross-role opening");
    unsigned char response[128];
    ssize_t received = recv(descriptor, response, sizeof(response), 0);
    if (received > 0) {
        unsigned char expected[12] = {0x01, 0x01, 0, 0, 4, 0, 0, 0, 20, 0, 0, 0};
        expected[0] = host_port == TCP_PORT ? 0x01 : 0x02;
        size_t length = (size_t)received;
        require(length <= sizeof(expected), "cross-role refusal carries no service bytes");
        while (length < sizeof(expected)) {
            received = recv(descriptor, response + length, sizeof(expected) - length, 0);
            require(received > 0, "complete cross-role protocol refusal");
            length += (size_t)received;
        }
        require(memcmp(response, expected, sizeof(expected)) == 0, "cross-role opening returns only a protocol refusal");
        received = recv(descriptor, response, sizeof(response), 0);
    }
    require(received == 0 || (received == -1 && (errno == ECONNRESET || errno == ENOTCONN)),
            "cross-role opening receives no network or agent service grant");
    require(close(descriptor) == 0, "close opening probe");
}

static void exercise_endpoints(int network_enabled) {
    char device[512];
    find_vsock_device(device, sizeof(device));
    FILE *abi = fopen("/sys/kernel/terra_socket_abi", "r");
    unsigned int version = 0;
    require(abi != NULL && fscanf(abi, "%u", &version) == 1 && version == TERRA_SOCKET_ABI,
            "matching kernel socket ABI");
    require(fclose(abi) == 0, "close kernel socket ABI");
    const char *obsolete[] = {"/dev/terra-agent-control", "/dev/terra-agent-session",
                              "/dev/terra-network-control", "/dev/terra-network-session"};
    for (unsigned int index = 0; index < sizeof(obsolete) / sizeof(obsolete[0]); index++)
        require(access(obsolete[index], F_OK) == -1 && errno == ENOENT, "custom channel device absent");
    int agent = duplicate_agent_vsock(AGENT_PORT);
    int duplicate = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(duplicate >= 0, "duplicate endpoint socket");
    struct sockaddr_vm local = {.svm_family = AF_VSOCK, .svm_cid = GUEST_CID, .svm_port = AGENT_PORT};
    require(bind(duplicate, (void *)&local, sizeof(local)) == -1 && errno == EADDRINUSE,
            "duplicate active agent endpoint rejected");
    require(close(duplicate) == 0 && close(agent) == 0, "close endpoint inspection");
    reject_endpoint(5998, UDP_PORT + 2);
    reject_endpoint(5998, AGENT_PORT);
    reject_endpoint(5998, CONTROL_PORT);
    reject_endpoint(5998, 0x100000);
    if (network_enabled) {
        int control = duplicate_agent_vsock(CONTROL_PORT);
        require(close(control) == 0, "close control inspection");
        reject_opening(5997, TCP_PORT, 4);
        reject_opening(TCP_PORT, TCP_PORT, 2);
        reject_opening(5996, UDP_PORT, 1);
    } else {
        reject_endpoint(5998, TCP_PORT);
        reject_endpoint(5998, UDP_PORT);
    }
    printf("VSOCK_ENDPOINT_CLASSES_OK device=%s\n", device);
}

/* Shut down the agent's network control stream, as a lost control connection would. */
static void stop_network_control(void) {
    int control = duplicate_agent_vsock(CONTROL_PORT);
    require(shutdown(control, SHUT_RDWR) == 0, "shut down the network control stream");
    require(close(control) == 0, "close network control duplicate");
    puts("NETWORK_CONTROL_STOPPED");
}

static void reset_shared_device(void) {
    char device[512], unbind[544];
    find_vsock_device(device, sizeof(device));
    write_marker("/work/SHARED_RESET_STARTED", (long)getpid(), 19);
    int length = snprintf(unbind, sizeof(unbind), "%s/driver/unbind", device);
    require(length > 0 && (size_t)length < sizeof(unbind), "vsock unbind path bound");
    int descriptor = open(unbind, O_WRONLY | O_CLOEXEC);
    require(descriptor >= 0, "open shared vsock unbind");
    const char *name = strrchr(device, '/') + 1;
    require(write(descriptor, name, strlen(name)) == (ssize_t)strlen(name), "unbind shared virtio-vsock device");
    close(descriptor);
    for (;;)
        pause();
}

static void read_credit_fixture(const char *path, unsigned char *bytes, size_t length) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC);
    require(descriptor >= 0, "open receive-credit fixture");
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = read(descriptor, bytes + offset, length - offset);
        require(count > 0, "read receive-credit fixture");
        offset += (size_t)count;
    }
    unsigned char extra;
    require(read(descriptor, &extra, 1) == 0, "exact receive-credit fixture length");
    require(close(descriptor) == 0, "close receive-credit fixture");
}

static void wait_credit_queue(int descriptor, int expected) {
    int queued = 0;
    for (int attempt = 0; attempt < 5000; attempt++) {
        require(ioctl(descriptor, FIONREAD, &queued) == 0, "observe receive-credit queue");
        if (queued == expected)
            return;
        usleep(1000);
    }
    fprintf(stderr, "receive-credit queue expected=%d observed=%d\n", expected, queued);
    errno = ETIMEDOUT;
    require(0, "receive-credit queue reaches expected size");
}

static void exercise_receive_credit_lowat(void) {
    unsigned char opening[36], expected_opened[32], opened[32];
    unsigned char expected[32 * 1024], received[32 * 1024];
    read_credit_fixture("/work/VSOCK_CREDIT_OPEN", opening, sizeof(opening));
    read_credit_fixture("/work/VSOCK_CREDIT_OPENED", expected_opened, sizeof(expected_opened));
    read_credit_fixture("/work/VSOCK_CREDIT_PAYLOAD", expected, sizeof(expected));
    int descriptor = socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0);
    require(descriptor >= 0, "create fresh TCP-flow carrier");
    uint64_t capacity = 24 * 1024;
    int options[] = {SO_VM_SOCKETS_BUFFER_MIN_SIZE, SO_VM_SOCKETS_BUFFER_MAX_SIZE,
                     SO_VM_SOCKETS_BUFFER_SIZE};
    for (size_t index = 0; index < sizeof(options) / sizeof(options[0]); index++)
        require(setsockopt(descriptor, AF_VSOCK, options[index], &capacity, sizeof(capacity)) == 0,
                "set 24-KiB carrier limits before connect");
    for (size_t index = 0; index < sizeof(options) / sizeof(options[0]); index++) {
        uint64_t value = 0;
        socklen_t length = sizeof(value);
        require(getsockopt(descriptor, AF_VSOCK, options[index], &value, &length) == 0 &&
                length == sizeof(value) && value == capacity, "verify 24-KiB carrier limits");
    }
    struct timeval timeout = {.tv_sec = 3};
    require(setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
            setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0,
            "bounded receive-credit stream operations");
    struct sockaddr_vm peer = {.svm_family = AF_VSOCK, .svm_cid = HOST_CID, .svm_port = TCP_PORT};
    require(connect(descriptor, (void *)&peer, sizeof(peer)) == 0, "connect admitted TCP-flow endpoint");
    int lowat = 0;
    socklen_t length = sizeof(lowat);
    require(getsockopt(descriptor, SOL_SOCKET, SO_RCVLOWAT, &lowat, &length) == 0 && lowat == 1,
            "default receive low-water is one byte");
    require(send(descriptor, opening, sizeof(opening), MSG_NOSIGNAL) == sizeof(opening),
            "send codec-derived valid TcpOpen");
    require(recv(descriptor, opened, sizeof(opened), MSG_WAITALL) == sizeof(opened) &&
            memcmp(opened, expected_opened, sizeof(opened)) == 0, "authorized TcpOpened reply");
    struct pollfd ready = {.fd = descriptor, .events = POLLIN};
    require(poll(&ready, 1, 3000) == 1 && (ready.revents & POLLIN),
            "default-low-water initial payload readiness");
    wait_credit_queue(descriptor, 4 * 1024);
    write_marker("/work/VSOCK_CREDIT_INITIAL", 4 * 1024, lowat);
    wait_credit_queue(descriptor, (int)capacity);
    lowat = 21 * 1024;
    require(setsockopt(descriptor, SOL_SOCKET, SO_RCVLOWAT, &lowat, sizeof(lowat)) == 0,
            "raise low-water before consuming initial skb");
    int observed_lowat = 0;
    length = sizeof(observed_lowat);
    require(getsockopt(descriptor, SOL_SOCKET, SO_RCVLOWAT, &observed_lowat, &length) == 0 &&
            observed_lowat == lowat, "high receive low-water is preserved");
    require(recv(descriptor, received, 4 * 1024, MSG_WAITALL) == 4 * 1024 &&
            memcmp(received, expected, 4 * 1024) == 0, "consume separate initial 4-KiB payload");
    ready.revents = 0;
    int polled = poll(&ready, 1, 3000);
    int queued = 0;
    require(ioctl(descriptor, FIONREAD, &queued) == 0, "observe high-low-water refill");
    fprintf(stderr, "receive-credit refill poll=%d events=%d queued=%d lowat=%d\n",
            polled, ready.revents, queued, lowat);
    require(polled == 1 && (ready.revents & POLLIN) && queued >= lowat,
            "credit update refills above high low-water before EOF");
    for (size_t offset = 4 * 1024; offset < sizeof(received); offset += 4 * 1024)
        require(recv(descriptor, received + offset, 4 * 1024, MSG_WAITALL) == 4 * 1024,
                "drain bounded receive-credit payload chunks");
    require(memcmp(received, expected, sizeof(received)) == 0, "receive-credit payload ordering");
    unsigned char extra;
    require(recv(descriptor, &extra, 1, 0) == 0, "receive-credit stream ends after full payload");
    require(shutdown(descriptor, SHUT_WR) == 0 && close(descriptor) == 0,
            "close both receive-credit stream halves");
    puts("VSOCK_RECEIVE_CREDIT_LOWAT_OK");
}

int main(int argc, char **argv) {
    alarm(30);
    if (argc == 2) {
        if (strcmp(argv[1], "receive-credit-lowat") == 0)
            exercise_receive_credit_lowat();
        else if (strcmp(argv[1], "endpoints") == 0 || strcmp(argv[1], "endpoints-network") == 0)
            exercise_endpoints(strcmp(argv[1], "endpoints-network") == 0);
        else if (strcmp(argv[1], "control-stop") == 0)
            stop_network_control();
        else {
            require(strcmp(argv[1], "shared-reset") == 0, "vsock probe mode");
            reset_shared_device();
        }
        return 0;
    }
    require(argc == 3, "expected host-service address and port");
    char *end = NULL;
    unsigned long port = strtoul(argv[2], &end, 10);
    require(end != argv[2] && *end == '\0' && port > 0 && port <= 65535, "port");
    struct sockaddr_in peer = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    require(inet_pton(AF_INET, argv[1], &peer.sin_addr) == 1, "host-service address");
    int descriptor = socket(AF_INET, SOCK_STREAM, 0);
    require(descriptor >= 0, "external socket");
    struct timeval timeout = {.tv_sec = 10};
    require(setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0,
            "receive timeout");
    require(connect(descriptor, (void *)&peer, sizeof(peer)) == 0, "external connection");
    unsigned char byte = 0;
    require(recv(descriptor, &byte, 1, 0) == 1 && byte == 0x5a, "external greeting");
    write_marker("/work/NETWORK_READ_WAITING", (long)getpid(), (long)SYS_recvfrom);
    ssize_t received = recv(descriptor, &byte, 1, 0);
    int received_error = errno;
    require(received == -1 && received_error == ECONNRESET, "control loss resets blocked receive");
    struct pollfd ready = {.fd = descriptor, .events = POLLIN | POLLOUT};
    require(poll(&ready, 1, 1000) == 1 && (ready.revents & (POLLHUP | POLLERR)) != 0,
            "control loss socket poll state");
    write_marker("/work/NETWORK_RESET_RESULT", received_error, ready.revents);
    printf("NETWORK_OWNER_RESET_SOCKET_OK errno=%d poll_events=%d\n", received_error, ready.revents);
    fflush(stdout);
    require(close(descriptor) == 0, "close disconnected socket");
    for (;;)
        pause();
}
