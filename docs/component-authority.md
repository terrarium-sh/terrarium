# Component authority

Every shipped component except the agent is compiled for `wasm32-unknown-unknown`.
The agent targets `wasm32-wasip3` so upstream Yamux can use the standard monotonic clock.
Its imports are read from the wrapped production artifact, rather than inferred
from its source WIT. [`check-component-authority.py`](../scripts/checks/check-component-authority.py)
compares that result with
[`component-authority.json`](../scripts/checks/component-authority.json), and
`component_imports` proves that boot and the interrupt controller link
with an empty linker. A new import or component fails `make verify` until this
inventory and its justification are reviewed.

A linker describes the host functions and resource types available to a
component. Different component roles receive different registration sets;
linkers with the same host-state type and grants can be reused across instances.
Resource handles and private Wasm memory remain scoped to each store. Guest RAM
is a native mapping shared by the VM and its device stores; memory imports
provide checked copies without exposing host pointers. Constructors
start with `wasmtime::component::Linker::new` and add their explicit imports.
Shared registration helpers cover common capabilities without giving every
component the union of all capabilities.

| Component | Imported authority | Why it is present and what bounds it |
| --- | --- | --- |
| Interrupt controller | None | Receives topology and operations through exports. Native code validates GSI, vector, destination and cleanup outputs. |
| VMM | VM/vCPU resources; lifecycle events; narrow MMIO `access` | The VM worker owns the prepared machine and can only issue an MMIO access. Resource methods are scoped to that machine. |
| Boot | None | Receives machine configuration and kernel bytes through exports. Native code validates every segment and write before copying into bounded guest RAM. |
| Block | Guest RAM, interrupt, disk capacity/read/write/discard/sync | One fixed-capacity disk grant and its assigned interrupt line; every disk range is checked. |
| Filesystem | Guest RAM, interrupt, selected filesystem descriptor/preopen methods, `wait-for` | One recipe-selected directory preopen. Descriptor resource methods are registered individually; clock types carry timestamps and do not grant a clock call. |
| Memory | Guest RAM, interrupt, discard | Reclaims checked ranges of the assigned guest RAM only. |
| Vsock frontend | Guest RAM, assigned interrupt, fixed bounded agent pipe, broker TCP/UDP/DNS methods, configured listener grants and monotonic `wait-for` | Owns one device, per-socket TCP and UDP streams, the agent network control stream and frontend-initiated publication streams. Broker authorization remains authoritative. No agent filesystem/session or VM/vCPU imports. |
| Agent | Fixed bounded agent endpoint, supplied authorized local clients and control streams, monotonic/system clocks, WASI CLI interfaces | Services retain host authorization. No guest RAM, interrupt, broker or arbitrary filesystem imports. Standard-library CLI bindings receive an empty environment, closed stdin and output sinks. |

Native MMIO routing connects each device request/reply stream directly. The host
validates device mappings, access widths, reply sequences and deadlines; routing
has no separate Wasm store. Network policy validation and enforcement use
`terra-policy` natively in the CLI and broker.

The host validates each boot plan and stamps its clock and random seed before
the agent receives the plan. The agent retains clocks for live clock updates;
its event subscription starts the worker, and stream closure signals completion.
Diagnostic delivery waits for capacity in the bounded host log queue.

The `memory.read-ranges` import copies scattered input
buffers. The host validates every range before copying, limits each range to
16 KiB, each call to 32 ranges and 64 KiB total, and returns one concatenated
byte sequence. The import grants no address authority beyond `memory.read`.

The filesystem `release-descriptor` import consumes an owned descriptor and waits
for its host handle to close before retrying directory removal on Windows. It can
only release a descriptor already held by that component store.

The checked list is exact, including resource destructors and empty imported
type interfaces. For the individual function names, see the machine-readable
allowlist. The native linker implementations and their focused negative tests
live with the capability they expose: filesystem descriptors in
`component/fs/resource_linker.rs`, broker operations in
`component/network/broker_linker.rs`, and service isolation in
`tests/integration/component_imports.rs` and
`tests/integration/component_grants.rs`.

The combined frontend owns device interrupts, guest-memory copies and network
parsing, with broker methods registered directly in its store. The fixed agent
pipe carries agent bytes to a separate store without RAM, IRQ or broker imports.
TCP opens carry one typed `inline-urgent` boolean (the broker sets
`SO_OOBINLINE` before connecting); the interface exposes no generic
socket-option operation. Stream semantics are defined in the
[network transport](../README.dev.md#network-transport).

This inventory limits a malicious or faulty component to its private Wasm memory
and its granted calls; [the security model](security.md#runtime-boundary) covers
the rest of the boundary. A guest-RAM grant permits reads and writes anywhere in
that VM's mapped RAM, not just the device's queue buffers, so devices are not
isolated from corrupting their own guest.
