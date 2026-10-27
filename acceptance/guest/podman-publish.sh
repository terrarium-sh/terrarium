cd /tmp
tar -C / -chf busybox.tar bin/busybox "lib/ld-musl-$(uname -m).so.1"
podman import -q busybox.tar localhost/busybox >/dev/null
podman run -d -p 8080:80 localhost/busybox /bin/busybox sh -c 'while true; do printf "HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\nCONTAINER_NETWORK" | /bin/busybox nc -l -p 80; done' >/dev/null
