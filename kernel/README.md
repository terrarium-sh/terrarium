# Guest kernel

The build applies `patches/*.patch` in filename order to the pinned Linux source,
then copies `overlay/` into that source tree. Files in the overlay use their Linux
source paths; edit Terra's socket adapter there and keep upstream changes in patches.

`make kernel` builds the configured architecture. `make kernel-export` packages
the image, resolved configuration, and input fingerprint for verified reuse.
The fingerprint includes the source pin, configuration, patches, overlay, and
builder recipe. Run `python3 -B scripts/kernel/test-kernel-vsock.py` for the socket adapter
and transport harness checks.

The first external UDP use opens its carrier synchronously. `MSG_DONTWAIT` does
not make that initial connection and opening handshake nonblocking.
