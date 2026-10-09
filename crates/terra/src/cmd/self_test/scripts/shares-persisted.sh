test "$(cat /work/host-update)" = LIVE_UPDATE
for i in $(seq 1 100); do
    test $(wc -l < /work/daemon) -lt 2 || break
    sleep .1
done
test $(wc -l < /work/daemon) -ge 2
echo PERSISTED > /data/value
sync
