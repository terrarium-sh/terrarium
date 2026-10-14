busybox --list | grep -qx inotifyd
for i in $(seq 1 100); do
    if test -f /tmp/workload-watcher-pid; then
        pid=$(cat /tmp/workload-watcher-pid)
        test $(grep -h '^inotify wd:' /proc/$pid/fdinfo/* | wc -l) -lt 2 || exit 0
    fi
    sleep .1
done
exit 1
