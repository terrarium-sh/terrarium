# Shared component interfaces

Terra contracts live in `terra/` (host capabilities and block API), `mmio/`
(device MMIO streams), `vmm/` (VM lifecycle and vCPU resources),
`network/` (restricted broker methods), and
`vsock/` (the fixed agent pipe). Pinned upstream WASI packages live in `wasi/`;
see [their provenance](wasi/README.md).

Component WIT directories use relative symbolic links to these sources. Git
stores the links, not copies of their contents. Edit the shared definition;
there is no mirror-generation step. Each component world still explicitly
selects its imports and exports: sharing a package does not grant its interfaces.

`terra:mmio/device.serve` carries device reads, writes, reset and close.
Device interfaces retain configuration and device-specific operations;
they share `terra:mmio/types.device-error` instead of defining their own copies.

## Capability boundary

A dependency package supplies definitions, not authority. Only imported interfaces
that the native linker implements can be called. For example, memory sees the
shared host definitions but receives no disk, filesystem, socket or VM interface.

| Component | Component-specific host capabilities |
| --- | --- |
| block | Bounded guest RAM, its interrupt, its disk grant |
| fs | Bounded guest RAM, its interrupt, preopened filesystem grants |
| mem | Bounded guest RAM, its interrupt, bounded page discard |
| vsock-frontend | Bounded guest RAM, its interrupt, fixed agent pipe, policy-controlled TCP/UDP and DNS, trusted listener grants |
| agent | Fixed agent stream, prebound authorized local clients, host-enriched plan, stop stream and clocks |
| boot | No host functions; supplied machine configuration and kernel prefix |
| vmm | VM lifecycle, vCPU execution, MMIO client and lifecycle events |
| interrupt-controller | No host functions; supplied topology and value-based operations |

Frontend timers bound opening deadlines; the native broker owns peer and DNS
expiry. Agent uses timers and system time for guest clock synchronization. The
host validates the boot plan and adds its clock and random seed. Filesystem WIT depends
on clock types for timestamps; that dependency alone does not grant a clock call.

Components except agent build for `wasm32-unknown-unknown` to avoid implicit WASI
services from the Rust standard library. Agent targets `wasm32-wasip3` so upstream
Yamux can use the standard monotonic clock. Its WASI imports are checked with the
same authority inventory and linked explicitly. Clock access uses explicit WIT imports
only where protocol timers or guest clock synchronization require it.

The [component authority inventory](../../docs/component-authority.md) records each
remaining imported function and resource scope. `component_imports` checks every
built component artifact. `component_grants` probes native linkers: only VMM receives VM/vCPU
resources, boot and the interrupt controller require no host functions, and device-specific filesystem,
socket and local-client resources remain restricted.

The combined device/network frontend and agent use separate stores. Agent
receives no guest-memory, interrupt or broker imports; the frontend receives
no agent services. Network requests go directly from the frontend to the
restricted broker, while the fixed pipe carries only agent bytes. Actual
artifact imports and native linkers must enforce the [authority inventory](../../docs/component-authority.md).

`make verify-wit` checks that the links resolve inside this directory. Component
builds run this check before parsing and compiling the interfaces.

On Windows, enable Developer Mode or use an account with symlink privileges and
clone with `git -c core.symlinks=true clone <repository>`. Windows CI sets
`core.symlinks` before checkout. A checkout that materializes links as text files
is rejected by the link check.
