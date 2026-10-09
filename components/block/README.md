# Block device component

`terra-block-component` is the WebAssembly virtio-blk device. It parses guest
queues and carries reads, writes, flushes and discards to this instance's fixed
disk grant. Guest-memory copies and the device interrupt use explicit host
imports.

Shared MMIO and split-ring mechanics are in [device-transport](../device-transport/src/lib.rs).
The device implementation and host interface are in [lib.rs](src/lib.rs) and
[host.wit](wit/host.wit); the native [BlockHost](../../crates/terra-runtime/src/component/block/host.rs)
supplies the disk grant and device context.
