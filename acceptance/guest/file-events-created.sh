for i in $(seq 1 100); do
    if grep -q '^c.*host-update' /tmp/workload-events && grep -q '^n.*host-created' /tmp/workload-events; then
        test $(cat /work/host-update) = LIVE_UPDATE
        test $(cat /work/host-created) = CREATED
        exit 0
    fi
    sleep .1
done
cat /tmp/workload-events
exit 1
