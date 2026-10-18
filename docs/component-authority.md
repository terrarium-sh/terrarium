# Component authority

Each Wasm component can call only the host functions it is given. This page
lists what each component imports and why.

## How the list is checked

[`check-component-authority.py`](../scripts/checks/check-component-authority.py)
reads the imports from each built production component and compares them with
[`component-authority.json`](../scripts/checks/component-authority.json). The
list is exact, down to resource destructors and empty type interfaces. A new
import or component fails `make verify` until the list and its reason are
reviewed. The `component_imports` test also proves that boot and the interrupt
controller link with an empty linker.

Components target `wasm32-unknown-unknown`. The agent targets `wasm32-wasip3`
so upstream Yamux can use the standard monotonic clock.

## Imports

| Component | Imports | Why, and what bounds it |
| --- | --- | --- |
| Interrupt controller (x86 only) | None | Gets its routes and operations through exports. Native code validates every line, vector, destination and cleanup it returns. |
| VMM | VM and vCPU resources, lifecycle events | Resources are scoped to the prepared machine. |
| Boot | None | Gets the machine configuration and kernel through exports. Native code validates every segment and write before copying into guest RAM. |
| Block | Guest RAM, interrupt, disk read/write/discard/sync | One fixed-size disk and its interrupt line; every disk range is checked. |
| Filesystem | Guest RAM, interrupt, selected filesystem methods, `wait-for` | One recipe-selected directory. Clock types carry timestamps but grant no clock call. |
| Memory | Guest RAM, interrupt, discard | Reclaims checked ranges of its own VM's RAM only. |
| Vsock frontend | Guest RAM, interrupt, the agent pipe, broker TCP/UDP/DNS methods, configured listeners, `wait-for` | Runs the one vsock device and its network streams. The broker still authorizes every connection. No agent, filesystem or VM imports. |
| Agent | The agent endpoint, authorized service streams, clocks, WASI CLI | No guest RAM, interrupt, broker or filesystem imports. Its environment is empty, stdin is closed and output goes to sinks. |

## How grants are wired

Every linker starts from `wasmtime::component::Linker::new` and adds only that
role's imports. Shared helpers register common capabilities without giving a
component the union of all of them. Each store keeps its own Wasm memory and
resource handles.

- **Guest RAM.** The VM and its devices share one native mapping. Memory
  imports make checked copies and never expose host pointers.
  `memory.read-ranges` copies scattered buffers in one call: the host checks
  every range, limits each range to 16 KiB, each call to 32 ranges and 64 KiB
  total, and grants no address range beyond `memory.read`.
- **Filesystem.** Descriptor methods are registered one by one.
  `release-descriptor` closes a descriptor the store already holds and waits
  for the host handle to close, so Windows can retry removing the directory.
- **Network.** The frontend owns device interrupts, guest-memory copies and
  packet parsing, and calls the broker directly. TCP opens carry typed options
  (`inline-urgent`, keepalive); there is no generic socket-option call. See
  [network transport](../README.dev.md#network-transport).
- **Agent.** A fixed, bounded pipe carries agent bytes from the frontend to the
  agent's own store. The host validates each boot plan and stamps its clock and
  random seed before the agent gets it. Diagnostics wait for room in the
  bounded host log queue.
- **Native, not Wasm.** MMIO routing has no Wasm store: native code connects
  each device's request/reply stream and checks mappings, access widths,
  replies and deadlines. Network policy runs as native `terra-policy` code in
  the CLI and broker.

The native linkers and their negative tests sit with the capability they grant:
`component/fs/resource_linker.rs`, `component/network/broker_linker.rs`, and
`tests/integration/component_imports.rs` and `component_grants.rs`.

## What this does not stop

A faulty or malicious component is limited to its own Wasm memory and the calls
it was granted; the [security model](security.md#layers-on-the-host) covers the
rest. A guest-RAM grant covers all of that VM's RAM, not just the device's
queues, so a device can still corrupt its own guest.
