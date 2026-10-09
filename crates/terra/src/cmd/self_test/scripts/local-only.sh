set -eu
printf 'HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nLOOPBACK' | busybox nc -l -p 18081 &
server=$!
trap 'kill $server 2>/dev/null || true' EXIT
for i in $(seq 1 50); do
    body=$(wget -q -T 1 -O - http://127.0.0.1:18081/) && break
    sleep .1
done
test "${body:-}" = LOOPBACK
wait $server
if wget -q -T 1 -O - http://192.0.2.1:80/; then exit 1; fi
echo LOCAL_ONLY_OK
