test "$(cat /etc/workload-probe)" = ROOT_WRITE
test -e /proc/self/ns/user
test -e /proc/self/ns/net
test -e /proc/self/ns/pid
