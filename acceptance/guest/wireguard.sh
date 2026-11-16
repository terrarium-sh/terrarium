set -eu

if [ "$(id -u)" -ne 0 ]; then
    failure_log=$(mktemp)
    trap 'rm -f "$failure_log"' EXIT
    status=0
    timeout 5 wireguard-go -f wg-denied > "$failure_log" 2>&1 || status=$?
    if [ "$status" -ne 1 ] ||
        ! grep -Eq 'Failed to create TUN device:.*(operation not permitted|permission denied)' "$failure_log"; then
        cat "$failure_log" >&2
        echo 'WireGuard TUN creation did not fail with a permission error without guest root' >&2
        exit 1
    fi
    echo WIREGUARD_UNPRIVILEGED_OK
    exit 0
fi

umask 077
keys=$(mktemp -d)
wireguard_pids=
cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        cat "$keys"/wg-*.log >&2 2>/dev/null || true
    fi
    for pid in $wireguard_pids; do kill "$pid" 2>/dev/null || true; done
    for pid in $wireguard_pids; do wait "$pid" 2>/dev/null || true; done
    ip link del wg-left 2>/dev/null || true
    ip link del wg-right 2>/dev/null || true
    ip netns del wg-left 2>/dev/null || true
    ip netns del wg-right 2>/dev/null || true
    rm -rf "$keys"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

start_wireguard() {
    wireguard-go -f "$1" > "$keys/$1.log" 2>&1 &
    pid=$!
    wireguard_pids="$wireguard_pids $pid"
    for attempt in $(seq 1 50); do
        if ! kill -0 "$pid" 2>/dev/null; then break; fi
        if [ -S "/var/run/wireguard/$1.sock" ] &&
            ip link show "$1" >/dev/null 2>&1 && wg show "$1" >/dev/null 2>&1; then
            return
        fi
        sleep .1
    done
    cat "$keys/$1.log" >&2
    echo "WireGuard interface $1 did not become ready" >&2
    exit 1
}

reset_peers() {
    wg set wg-left peer "$right_public" remove
    wg set wg-right peer "$left_public" remove
    wg set wg-left peer "$right_public" allowed-ips 0.0.0.0/0,::/0 endpoint "$1"
    wg set wg-right peer "$left_public" allowed-ips 192.0.2.1/32,fd00::1/128
}

exercise_tunnel() {
    ip netns exec wg-left ping -c 2 -W 5 -s 1200 192.0.2.2
    ip netns exec wg-right ping -c 2 -W 5 -s 1200 192.0.2.1
    ip netns exec wg-left ping -6 -c 2 -W 5 -s 1200 fd00::2
    ip netns exec wg-right ping -6 -c 2 -W 5 -s 1200 fd00::1
    ip netns exec wg-left ping -c 2 -W 5 -s 1200 198.51.100.2
    ip netns exec wg-left ping -6 -c 2 -W 5 -s 1200 fd01::2

    for side in wg-left wg-right; do
        wg show "$side" latest-handshakes |
            awk -v now="$(date +%s)" '$2 == 0 || $2 > now || now - $2 > 60 { exit 1 } END { if (NR != 1) exit 1 }'
        wg show "$side" transfer |
            awk '$2 == 0 || $3 == 0 { exit 1 } END { if (NR != 1) exit 1 }'
    done
}

wg genkey > "$keys/left"
wg genkey > "$keys/right"
left_public=$(wg pubkey < "$keys/left")
right_public=$(wg pubkey < "$keys/right")

ip netns add wg-left
ip netns add wg-right
# The daemons keep outer UDP sockets outside the namespaces' default tunnel routes.
start_wireguard wg-left
start_wireguard wg-right
wg set wg-left private-key "$keys/left" listen-port 51820
wg set wg-right private-key "$keys/right" listen-port 51821
reset_peers 127.0.0.1:51821
ip link set wg-left netns wg-left
ip link set wg-right netns wg-right

ip -n wg-left address add 192.0.2.1/24 dev wg-left
ip -n wg-right address add 192.0.2.2/24 dev wg-right
ip -n wg-left -6 address add fd00::1/64 dev wg-left nodad
ip -n wg-right -6 address add fd00::2/64 dev wg-right nodad
ip -n wg-right address add 198.51.100.2/32 dev lo
ip -n wg-right -6 address add fd01::2/128 dev lo nodad
for side in wg-left wg-right; do
    ip -n "$side" link set lo up
    ip -n "$side" link set "$side" mtu 1280 up
    ip -n "$side" route add default dev "$side"
    ip -n "$side" -6 route add default dev "$side"
done

exercise_tunnel
reset_peers "gate.test:${1:?missing allowed UDP port}"
exercise_tunnel

wg set wg-right peer "$left_public" allowed-ips fd00::1/128
if ip netns exec wg-left ping -c 1 -W 1 192.0.2.2; then
    echo 'WireGuard accepted an address outside peer allowed-ips' >&2
    exit 1
fi
ip netns exec wg-left ping -6 -c 1 -W 3 fd00::2

wg genkey > "$keys/unknown"
unknown_public=$(wg pubkey < "$keys/unknown")
wg set wg-right peer "$left_public" remove
wg set wg-right peer "$unknown_public" allowed-ips fd00::1/128
if ip netns exec wg-left ping -6 -c 1 -W 1 fd00::2; then
    echo 'WireGuard accepted an unknown peer' >&2
    exit 1
fi
wg set wg-right peer "$unknown_public" remove

reset_peers "gate.test:${2:?missing denied UDP port}"
if ip netns exec wg-left ping -c 1 -W 3 192.0.2.2; then
    echo 'WireGuard reached a UDP port outside the network allowlist' >&2
    exit 1
fi
for side in wg-left wg-right; do
    wg show "$side" latest-handshakes |
        awk '$2 != 0 { exit 1 } END { if (NR != 1) exit 1 }'
done
echo WIREGUARD_OK
