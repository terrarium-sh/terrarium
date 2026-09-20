#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <time.h>

int main(int argc, char **argv) {
    if (argc != 5) return 2;
    int fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    unsigned mask = IN_CREATE | IN_DELETE | IN_MODIFY | IN_ATTRIB | IN_DELETE_SELF;
    int directory = inotify_add_watch(fd, argv[1], mask);
    char path[4096];
    snprintf(path, sizeof(path), "%s/%s", argv[1], argv[2]);
    int file = inotify_add_watch(fd, path, mask);
    if (fd < 0 || directory < 0) return 3;
    FILE *cached = fopen(path, "r");
    if (cached) {
        char contents[256];
        fread(contents, 1, sizeof(contents), cached);
        fclose(cached);
    }
    int ready = open(argv[3], O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (ready < 0) return 4;
    close(ready);
    int saw_directory = 0, saw_file = file < 0;
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec >= 20) break;
        struct pollfd pollfd = { .fd = fd, .events = POLLIN };
        if (poll(&pollfd, 1, 200) <= 0) continue;
        char bytes[16384] __attribute__((aligned(__alignof__(struct inotify_event))));
        ssize_t count = read(fd, bytes, sizeof(bytes));
        for (ssize_t offset = 0; offset < count;) {
            struct inotify_event *event = (void *)(bytes + offset);
            if (event->wd == directory && event->len && !strcmp(event->name, argv[2]))
                saw_directory = 1;
            if (event->wd == file && (event->mask & mask)) saw_file = 1;
            offset += sizeof(*event) + event->len;
        }
        if (saw_directory && saw_file) {
            if (strcmp(argv[4], "absent")) {
                FILE *source = fopen(path, "r");
                char contents[256] = {0};
                if (!source) return 5;
                fread(contents, 1, sizeof(contents) - 1, source);
                fclose(source);
                if (strcmp(contents, argv[4])) continue;
            } else if (!access(path, F_OK)) continue;
            puts("FILE_EVENTS_OK");
            close(fd);
            return 0;
        }
    }
    fprintf(stderr, "missing notifications: directory=%d file=%d\n", saw_directory, saw_file);
    return 6;
}
