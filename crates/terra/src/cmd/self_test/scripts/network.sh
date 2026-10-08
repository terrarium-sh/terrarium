pids=
for index in $(seq 1 {concurrent_network_flows}); do
    (test "$(wget -q -T 5 -O - http://gate.test:{allowed_port}/)" = HOST_NETWORK) &
    pids="$pids $!"
done
for pid in $pids; do
    wait "$pid"
done
if wget -q -T 2 -O - http://gate.test:{denied_port}/; then exit 1; fi
if wget -q -T 2 -O - http://blocked.invalid:{allowed_port}/; then exit 1; fi
if nslookup blocked.invalid; then exit 1; fi
reply=$(printf terra-udp | busybox nc -u -w 1 gate.test {allowed_port} || true)
test "$reply" = HOST_DATAGRAM
reply=$(printf terra-udp | busybox nc -u -w 1 gate.test {denied_port} || true)
test -z "$reply"
