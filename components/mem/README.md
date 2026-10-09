# Memory device component

`terra-mem-component` implements the guest-facing virtio-balloon device. It
services the balloon queues and handles page-reporting ranges, asking the host
to discard eligible pages from this VM's guest RAM.

Its WIT imports provide bounded guest-memory copies, this device's interrupt
and the page-discard operation. See [transport.rs](src/transport.rs),
[lib.rs](src/lib.rs), [mem.wit](wit/mem.wit), and the native
[memory host adapter](../../crates/terra-runtime/src/component/mem/host.rs).
