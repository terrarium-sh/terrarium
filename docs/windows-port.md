# Windows support

Windows is not supported by the current tree.

`terra` has a Unix-only platform layer. The crate deliberately fails to
compile on non-Unix targets, and its VM/control path uses Unix file descriptors,
Unix sockets and signals. The vendored libkrun also lacks a Windows VMM backend
and currently has Unix-only dependency assumptions.

The Windows target is therefore a porting target, not a supported build:

```sh
cargo check -p terra --target x86_64-pc-windows-gnu
```

That check is expected to fail until both sides are ported. A complete port
needs, at minimum:

- a `crates/terra/src/sys/windows.rs` platform implementation for sockets,
  descriptors, ownership, stdio handover and graceful-stop signalling;
- conditional dependency features for the Windows target;
- a Windows-capable libkrun VMM, vsock and virtio-net implementation; and
- Windows build and runtime tests before the target can be documented as
  supported.

Until then, use Linux for KVM and Apple Silicon macOS for the supported
Hypervisor.framework target. See [README.dev.md](../README.dev.md) for the
current platform matrix.
