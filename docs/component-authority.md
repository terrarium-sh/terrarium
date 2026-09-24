# Component authority

Every shipped component except vsock is compiled for `wasm32-unknown-unknown`.
Vsock targets `wasm32-wasip3` so upstream Yamux can use the standard monotonic clock.
Its imports are read from the wrapped production artifact, rather than inferred
from its source WIT. [`check-component-authority.py`](../scripts/check-component-authority.py)
compares that result with
[`component-authority.json`](../scripts/component-authority.json), and
`component_imports` proves that MMIO and the interrupt controller link
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
| MMIO | None | Receives only mappings and device streams through exports. Native code validates returned slots and access ranges. |
| Interrupt controller | None | Receives topology and operations through exports. Native code validates GSI, vector, destination and cleanup outputs. |
| VMM | VM/vCPU resources; lifecycle events; narrow MMIO `access` | The VM worker owns the prepared machine and can only issue an MMIO access. Resource methods are scoped to that machine. |
| Boot | Kernel copy, prefix/size, machine configuration and bounded RAM writes | A short-lived boot store writes only the prepared VM's bounded RAM and is destroyed before VMM startup. |
| Block | Guest RAM, interrupt, disk capacity/read/write/discard/sync | One fixed-capacity disk grant and its assigned interrupt line; every disk range is checked. |
| Filesystem | Guest RAM, interrupt, selected filesystem descriptor/preopen methods, `wait-for` | One recipe-selected directory preopen. Descriptor resource methods are registered individually; clock types carry timestamps and do not grant a clock call. |
| Memory | Guest RAM, interrupt, discard | Reclaims checked ranges of the assigned guest RAM only. |
| Network | Guest RAM, interrupt, diagnostics, policy-filtered socket/DNS methods, monotonic `now`/`wait-for` | Socket resources are created and used through policy-enforcing hosts. The only diagnostic sink is capped logging. |
| Vsock | Guest RAM, interrupt, supplied local clients and control streams, monotonic/system clocks, `get-random-u64`, WASI CLI interfaces | Local listener/client resources come from the configured box service; randomness seeds the guest service. The standard-library CLI bindings receive an empty environment, closed stdin, and output sinks. No general filesystem or sockets are linked. |
| Policy | Monotonic `now` | Computes policy and DNS-expiry decisions with no Terra host, guest RAM, filesystem or socket imports. |

The checked list is exact, including resource destructors and empty imported
type interfaces. For the individual function names, see the machine-readable
allowlist. The native linker implementations and their focused negative tests
live with the capability they expose: filesystem descriptors in
`component/fs/resource_linker.rs`, sockets in
`component/network/resource_linker.rs`, and service isolation in
`tests/component_imports.rs` and `tests/component_grants.rs`.

This capability inventory is part of the component SFI boundary described in
[the security model](security.md). It limits a malicious or faulty component to
its private Wasm memory and its explicitly granted calls. A guest-RAM grant
permits reads and writes anywhere in that VM's mapped RAM, not just the device's
queue buffers; it does not isolate devices from corrupting the same guest.
Native code remains responsible for allocation, mappings, copy-size and address
validation, and page reclamation. Wasmtime, the native adapters,
the hypervisor, trusted artifacts and the host kernel remain in the trusted
computing base.
