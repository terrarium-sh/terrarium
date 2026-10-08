for i in $(seq 1 100); do
    test ! -f /work/ready || break
    sleep .1
done
test -f /work/ready
test $(wc -l < /opt/workload/bake) = 1
test -s /terra/recipe
test $(nproc) = 2
