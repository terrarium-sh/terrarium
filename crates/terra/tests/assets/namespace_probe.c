#define _GNU_SOURCE
#include <sched.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int flags = CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC |
                CLONE_NEWNET | CLONE_NEWPID | CLONE_NEWCGROUP | CLONE_NEWTIME;
    if (unshare(flags) != 0) {
        perror("unshare");
        return 1;
    }
    int tun = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (tun < 0) {
        perror("open /dev/net/tun");
        return 6;
    }
    struct ifreq request = { .ifr_flags = IFF_TUN | IFF_NO_PI };
    if (ioctl(tun, TUNSETIFF, &request) != 0) {
        perror("TUNSETIFF in guest user/network namespace");
        return 7;
    }
    close(tun);
    pid_t child = fork();
    if (child < 0)
        return 2;
    if (child == 0)
        _exit(getpid() == 1 ? 0 : 3);
    int status;
    if (waitpid(child, &status, 0) != child)
        return 4;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 5;
}
