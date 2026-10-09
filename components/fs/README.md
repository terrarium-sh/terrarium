# Filesystem component

`terra-fs-component` is the WebAssembly virtio-fs device. It parses FUSE
requests from guest queues and serves filesystem operations and file events
over the MMIO device interface.

The native [FsHost](../../crates/terra-runtime/src/component/fs/host.rs)
preopens the selected share at `/` and supplies this device's guest-memory and
interrupt imports. The protocol and grants are described in
[the transport](src/transport.rs), [wire format](src/wire.rs), and
[fs.wit](wit/fs.wit).
