grep -q ' - cgroup2 ' /proc/self/mountinfo
mkdir -p /tmp/overlay/lower /tmp/overlay/upper /tmp/overlay/work /tmp/overlay/merged
echo lower > /tmp/overlay/lower/value
mount -t overlay overlay -o lowerdir=/tmp/overlay/lower,upperdir=/tmp/overlay/upper,workdir=/tmp/overlay/work /tmp/overlay/merged
test $(cat /tmp/overlay/merged/value) = lower
echo upper > /tmp/overlay/merged/value
test $(cat /tmp/overlay/upper/value) = upper
umount /tmp/overlay/merged
