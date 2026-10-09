for i in $(seq 1 100); do
    if grep -q '^d.*host-created' /tmp/workload-events; then
        test ! -e /work/host-created
        exit 0
    fi
    sleep .1
done
cat /tmp/workload-events
exit 1
