test $(id -u) = 0
test $(cat /data/value) = PERSISTED
test $(wc -l < /opt/workload/bake) = 1
echo CHANGED > /data/value
sync
echo RESTART_OK
