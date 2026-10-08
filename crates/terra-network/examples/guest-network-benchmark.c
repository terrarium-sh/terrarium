#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum { TCP_CHUNK = 8192, UDP_BYTES = 1200, UDP_WINDOW = 32, LATENCY_BYTES = 64, WARMUP = 50 };

static void require(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "network benchmark: %s (errno %d)\n", message, errno);
        exit(1);
    }
}

static double seconds(void) {
    struct timespec timestamp;
    require(clock_gettime(CLOCK_MONOTONIC, &timestamp) == 0, "read monotonic clock");
    return (double)timestamp.tv_sec + (double)timestamp.tv_nsec / 1000000000.0;
}

static void send_all(int fd, const unsigned char *bytes, size_t length) {
    while (length != 0) {
        ssize_t count = send(fd, bytes, length, 0);
        if (count < 0 && errno == EINTR)
            continue;
        require(count > 0, "send TCP bytes");
        bytes += (size_t)count;
        length -= (size_t)count;
    }
}

static void receive_exact(int fd, unsigned char *bytes, size_t length) {
    while (length != 0) {
        ssize_t count = recv(fd, bytes, length, 0);
        if (count < 0 && errno == EINTR)
            continue;
        require(count > 0, "receive TCP bytes before EOF or deadline");
        bytes += (size_t)count;
        length -= (size_t)count;
    }
}

static int connect_peer(const char *host, const char *port, int is_udp) {
    struct addrinfo hints = {0}, *addresses = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = is_udp ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    require(getaddrinfo(host, port, &hints, &addresses) == 0, "resolve benchmark host");
    require(addresses != NULL, "resolution returned no address");
    int fd = socket(addresses->ai_family, addresses->ai_socktype, addresses->ai_protocol);
    require(fd >= 0, "create benchmark socket");
    struct timeval timeout = {.tv_sec = 10, .tv_usec = 0};
    require(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "set receive deadline");
    require(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0, "set send deadline");
    if (!is_udp) {
        int enabled = 1;
        require(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)) == 0, "disable Nagle delay");
    }
    require(connect(fd, addresses->ai_addr, addresses->ai_addrlen) == 0, "connect benchmark peer");
    freeaddrinfo(addresses);
    return fd;
}

static void prepare_tcp(int fd, unsigned char mode, uint64_t count) {
    unsigned char header[9];
    header[0] = mode;
    for (size_t index = 0; index < 8; index++)
        header[index + 1] = (unsigned char)(count >> (index * 8));
    send_all(fd, header, sizeof(header));
    unsigned char acknowledgement;
    receive_exact(fd, &acknowledgement, 1);
    require(acknowledgement == 'R', "server readiness acknowledgement");
}

static void verify_payload(const unsigned char *bytes, size_t length) {
    for (size_t index = 0; index < length; index++)
        require(bytes[index] == 'Z', "TCP payload changed");
}

static void transfer_tcp(int fd, uint64_t count, int is_download) {
    unsigned char bytes[TCP_CHUNK];
    memset(bytes, 'Z', sizeof(bytes));
    if (is_download)
        send_all(fd, (const unsigned char *)"G", 1);
    for (uint64_t transferred = 0; transferred < count;) {
        size_t chunk = count - transferred < sizeof(bytes) ? (size_t)(count - transferred) : sizeof(bytes);
        if (is_download) {
            receive_exact(fd, bytes, chunk);
            verify_payload(bytes, chunk);
        } else {
            send_all(fd, bytes, chunk);
        }
        transferred += chunk;
    }
    if (!is_download) {
        unsigned char acknowledgement;
        receive_exact(fd, &acknowledgement, 1);
        require(acknowledgement == 'K', "upload byte count acknowledgement");
    }
}

static void measure_tcp(int fd, uint64_t count, int is_download) {
    prepare_tcp(fd, is_download ? 'D' : 'U', count);
    double started = seconds();
    transfer_tcp(fd, count, is_download);
    double elapsed = seconds() - started;
    printf("{\"case\":\"tcp_%s\",\"bytes\":%llu,\"seconds\":%.9f,\"mib_per_second\":%.6f}\n",
           is_download ? "download" : "upload", (unsigned long long)count, elapsed,
           (double)count / (1024.0 * 1024.0) / elapsed);
}

struct tcp_transfer {
    int fd;
    uint64_t count;
    int is_download;
    pthread_barrier_t *start;
};

static void wait_for_transfers(pthread_barrier_t *start) {
    int result = pthread_barrier_wait(start);
    require(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD, "release TCP transfers");
}

static void *run_tcp_transfer(void *argument) {
    struct tcp_transfer *transfer = argument;
    wait_for_transfers(transfer->start);
    transfer_tcp(transfer->fd, transfer->count, transfer->is_download);
    return NULL;
}

static void measure_concurrent_tcp(const char *host, const char *port, uint64_t count,
                                   int is_download, size_t concurrency) {
    pthread_barrier_t start;
    require(pthread_barrier_init(&start, NULL, (unsigned)concurrency + 1) == 0, "initialize TCP start barrier");
    pthread_t threads[64];
    struct tcp_transfer transfers[64];
    for (size_t index = 0; index < concurrency; index++) {
        int fd = connect_peer(host, port, 0);
        prepare_tcp(fd, is_download ? 'D' : 'U', count);
        transfers[index] = (struct tcp_transfer){fd, count, is_download, &start};
        require(pthread_create(&threads[index], NULL, run_tcp_transfer, &transfers[index]) == 0, "start TCP transfer");
    }
    double started = seconds();
    wait_for_transfers(&start);
    for (size_t index = 0; index < concurrency; index++)
        require(pthread_join(threads[index], NULL) == 0, "join TCP transfer");
    double elapsed = seconds() - started;
    uint64_t total = count * concurrency;
    printf("{\"case\":\"tcp_%s_concurrent_%zu\",\"bytes\":%llu,\"seconds\":%.9f,\"mib_per_second\":%.6f}\n",
           is_download ? "download" : "upload", concurrency, (unsigned long long)total,
           elapsed, (double)total / (1024.0 * 1024.0) / elapsed);
    for (size_t index = 0; index < concurrency; index++)
        require(close(transfers[index].fd) == 0, "close TCP transfer socket");
    require(pthread_barrier_destroy(&start) == 0, "destroy TCP start barrier");
}

static int compare_samples(const void *left, const void *right) {
    double first = *(const double *)left, second = *(const double *)right;
    return (first > second) - (first < second);
}

static void measure_churn(const char *host, const char *port, size_t count) {
    double *samples = calloc(count, sizeof(*samples));
    double *close_samples = calloc(count, sizeof(*close_samples));
    require(samples != NULL && close_samples != NULL, "allocate bounded connection samples");
    double started = seconds(), first_connect = 0, close_seconds = 0;
    unsigned char payload[LATENCY_BYTES], received[LATENCY_BYTES];
    memset(payload, 'Z', sizeof(payload));
    for (size_t index = 0; index < count; index++) {
        double connected = seconds();
        int fd = connect_peer(host, port, 0);
        if (index == 0)
            first_connect = seconds() - connected;
        prepare_tcp(fd, 'L', 1);
        send_all(fd, payload, sizeof(payload));
        receive_exact(fd, received, sizeof(received));
        require(memcmp(payload, received, sizeof(payload)) == 0, "connection churn payload changed");
        double close_started = seconds();
        require(close(fd) == 0, "close churn connection");
        double completed = seconds();
        close_seconds += completed - close_started;
        close_samples[index] = (completed - close_started) * 1000000.0;
        samples[index] = (completed - connected) * 1000000.0;
    }
    double elapsed = seconds() - started;
    qsort(samples, count, sizeof(*samples), compare_samples);
    qsort(close_samples, count, sizeof(*close_samples), compare_samples);
    printf("{\"case\":\"tcp_connection_churn\",\"samples\":%zu,\"seconds\":%.9f,\"connections_per_second\":%.6f,\"first_connect_us\":%.6f,\"p50_us\":%.6f,\"p95_us\":%.6f,\"close_seconds\":%.9f,\"close_p50_us\":%.6f,\"close_p95_us\":%.6f,\"close_max_us\":%.6f}\n",
           count, elapsed, count / elapsed, first_connect * 1000000.0, samples[count / 2], samples[count * 95 / 100],
           close_seconds, close_samples[count / 2], close_samples[count * 95 / 100], close_samples[count - 1]);
    free(samples);
    free(close_samples);
}

static void measure_localhost(uint64_t count) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    require(listener >= 0, "create guest localhost listener");
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    require(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0, "bind guest localhost");
    require(listen(listener, 1) == 0, "listen on guest localhost");
    socklen_t length = sizeof(address);
    require(getsockname(listener, (struct sockaddr *)&address, &length) == 0, "read guest localhost port");
    pid_t child = fork();
    require(child >= 0, "fork guest localhost server");
    if (child == 0) {
        int fd = accept(listener, NULL, NULL);
        require(fd >= 0, "accept guest localhost connection");
        unsigned char header[9], trigger, bytes[TCP_CHUNK];
        receive_exact(fd, header, sizeof(header));
        send_all(fd, (const unsigned char *)"R", 1);
        receive_exact(fd, &trigger, 1);
        require(trigger == 'G', "localhost download trigger");
        memset(bytes, 'Z', sizeof(bytes));
        for (uint64_t sent = 0; sent < count;) {
            size_t chunk = count - sent < sizeof(bytes) ? (size_t)(count - sent) : sizeof(bytes);
            send_all(fd, bytes, chunk);
            sent += chunk;
        }
        close(fd);
        close(listener);
        _exit(0);
    }
    close(listener);
    char port[6];
    snprintf(port, sizeof(port), "%u", ntohs(address.sin_port));
    int fd = connect_peer("127.0.0.1", port, 0);
    prepare_tcp(fd, 'D', count);
    double started = seconds();
    transfer_tcp(fd, count, 1);
    double elapsed = seconds() - started;
    require(close(fd) == 0, "close guest localhost client");
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "guest localhost server completed");
    printf("{\"case\":\"localhost_tcp_download\",\"bytes\":%llu,\"seconds\":%.9f,\"mib_per_second\":%.6f}\n",
           (unsigned long long)count, elapsed, (double)count / (1024.0 * 1024.0) / elapsed);
}

static void measure_latency(int fd, size_t count) {
    prepare_tcp(fd, 'L', (uint64_t)count + WARMUP);
    double *samples = calloc(count, sizeof(*samples));
    require(samples != NULL, "allocate bounded latency samples");
    unsigned char payload[LATENCY_BYTES], received[LATENCY_BYTES];
    memset(payload, 'Z', sizeof(payload));
    double elapsed = 0;
    for (size_t index = 0; index < count + WARMUP; index++) {
        double started = seconds();
        send_all(fd, payload, sizeof(payload));
        receive_exact(fd, received, sizeof(received));
        require(memcmp(payload, received, sizeof(payload)) == 0, "latency payload changed");
        if (index >= WARMUP) {
            double duration = seconds() - started;
            samples[index - WARMUP] = duration * 1000000.0;
            elapsed += duration;
        }
    }
    qsort(samples, count, sizeof(*samples), compare_samples);
    printf("{\"case\":\"tcp_64_byte_round_trip\",\"samples\":%zu,\"seconds\":%.9f,\"p50_us\":%.6f,\"p95_us\":%.6f}\n",
           count, elapsed, samples[count / 2], samples[count * 95 / 100]);
    free(samples);
}

static void measure_udp(int fd, size_t count) {
    unsigned char bytes[UDP_BYTES], received[UDP_BYTES + 1];
    memset(bytes, 'Z', sizeof(bytes));
    double started = seconds();
    for (size_t index = 0; index < count; index++) {
        uint64_t sequence = index;
        memcpy(bytes, &sequence, sizeof(sequence));
        require(send(fd, bytes, sizeof(bytes), 0) == sizeof(bytes), "send complete UDP datagram");
        require(recv(fd, received, sizeof(received), 0) == sizeof(bytes), "receive complete UDP datagram before deadline");
        require(memcmp(bytes, received, sizeof(bytes)) == 0, "UDP sequence or payload changed");
    }
    double elapsed = seconds() - started;
    size_t byte_count = count * UDP_BYTES;
    printf("{\"case\":\"udp_1200_byte_round_trip\",\"bytes\":%zu,\"datagrams\":%zu,\"seconds\":%.9f,\"mib_per_second\":%.6f}\n",
           byte_count, count, elapsed, (double)byte_count / (1024.0 * 1024.0) / elapsed);
}

/* Keep UDP_WINDOW echoes outstanding; a 1-second silence expires every outstanding datagram as lost. */
static void measure_udp_window(int fd, size_t count) {
    unsigned char bytes[UDP_BYTES], received[UDP_BYTES + 1];
    memset(bytes, 'Z', sizeof(bytes));
    struct timeval timeout = {.tv_sec = 1};
    require(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, "set UDP receive timeout");
    size_t sent = 0, delivered = 0, lost = 0;
    double started = seconds();
    while (delivered + lost < count) {
        for (; sent < count && sent - delivered - lost < UDP_WINDOW; sent++) {
            uint64_t sequence = sent;
            memcpy(bytes, &sequence, sizeof(sequence));
            require(send(fd, bytes, sizeof(bytes), 0) == sizeof(bytes), "send complete UDP datagram");
        }
        ssize_t length = recv(fd, received, sizeof(received), 0);
        if (length < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            lost = sent - delivered;
            continue;
        }
        require(length == UDP_BYTES, "receive complete UDP datagram");
        require(memcmp(bytes + sizeof(uint64_t), received + sizeof(uint64_t), UDP_BYTES - sizeof(uint64_t)) == 0,
                "UDP payload changed");
        delivered++;
    }
    double elapsed = seconds() - started;
    size_t byte_count = delivered * UDP_BYTES;
    printf("{\"case\":\"udp_1200_byte_window_32\",\"bytes\":%zu,\"datagrams\":%zu,\"lost_datagrams\":%zu,\"seconds\":%.9f,\"mib_per_second\":%.6f}\n",
           byte_count, count, lost, elapsed, (double)byte_count / (1024.0 * 1024.0) / elapsed);
}

int main(int argc, char **argv) {
    require(argc == 5 || argc == 6, "expected MODE HOST PORT COUNT [TCP_CONCURRENCY]");
    alarm(180);
    char *end;
    errno = 0;
    unsigned long long count = strtoull(argv[4], &end, 10);
    require(errno == 0 && *end == '\0' && count > 0 && count <= 1024ULL * 1024 * 1024, "count must be 1 through 1073741824");
    int is_udp_window = strcmp(argv[1], "udp-window") == 0;
    int is_udp = is_udp_window || strcmp(argv[1], "udp") == 0;
    int is_latency = strcmp(argv[1], "latency") == 0;
    int is_upload = strcmp(argv[1], "upload") == 0;
    int is_download = strcmp(argv[1], "download") == 0;
    int is_churn = strcmp(argv[1], "churn") == 0;
    int is_localhost = strcmp(argv[1], "localhost") == 0;
    require(is_udp || is_latency || is_upload || is_download || is_churn || is_localhost, "mode must be upload, download, latency, udp, udp-window, churn, or localhost");
    require(!(is_udp || is_latency || is_churn) || count <= 1000000, "sample count exceeds 1000000");
    unsigned long concurrency = 1;
    if (argc == 6) {
        errno = 0;
        concurrency = strtoul(argv[5], &end, 10);
        require(errno == 0 && *end == '\0' && concurrency > 0 && concurrency <= 64, "TCP concurrency must be 1 through 64");
        require(is_upload || is_download, "TCP concurrency needs upload or download mode");
        require(count <= UINT64_MAX / concurrency, "concurrent TCP byte count overflow");
    }
    if (concurrency > 1) {
        measure_concurrent_tcp(argv[2], argv[3], (uint64_t)count, is_download, (size_t)concurrency);
        return 0;
    }
    if (is_churn) {
        measure_churn(argv[2], argv[3], (size_t)count);
        return 0;
    }
    if (is_localhost) {
        measure_localhost((uint64_t)count);
        return 0;
    }
    int fd = connect_peer(argv[2], argv[3], is_udp);
    if (is_udp_window)
        measure_udp_window(fd, (size_t)count);
    else if (is_udp)
        measure_udp(fd, (size_t)count);
    else if (is_latency)
        measure_latency(fd, (size_t)count);
    else
        measure_tcp(fd, (uint64_t)count, is_download);
    require(close(fd) == 0, "close benchmark socket");
    return 0;
}
