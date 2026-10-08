# Device transport library

`terra-device-transport` is a Rust library for virtio-MMIO register state,
split-ring descriptors, queue entries, completions, doorbells and bounded
guest-memory batches. Block, filesystem, memory and vsock device components
reuse these mechanics; the agent shares the doorbell.

Keeping this code in a library lets the transport rules be tested independently
and shared without merging device implementations. The library has no Wasm
store, worker or WIT host imports; each consuming component's WIT world and
native linker define its authority. See [lib.rs](src/lib.rs), the
[component interfaces](../wit/README.md), and the
[authority inventory](../../docs/component-authority.md).
