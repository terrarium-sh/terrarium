# Shared component interfaces

Terra contracts live in `terra/` (host capabilities and block API) and `mmio/`
(MMIO streams and VMM interfaces). Pinned upstream WASI packages live in `wasi/`;
see [their provenance](wasi/README.md).

Component WIT directories use relative symbolic links to these sources. Git
stores the links, not copies of their contents. Edit the shared definition;
there is no mirror-generation step. Each component world still explicitly
selects its imports and exports: sharing a package does not grant its interfaces.

`terra:mmio/device.serve` carries device reads, writes, reset, close and interrupt
queries. Device interfaces retain configuration and device-specific operations;
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
| network | Bounded guest RAM, its interrupt, policy-controlled TCP/UDP and DNS |
| vsock | Bounded guest RAM, its interrupt, prebound local clients, plan/stop streams, secure randomness |
| boot | Kernel-image access and bounded boot writes for the prepared VM |
| vmm | VM lifecycle, vCPU execution, MMIO client and lifecycle events |
| mmio | No host functions; supplied mappings and per-device streams |
| interrupt-controller | No host functions; supplied topology and value-based operations |
| policy | No Terra host interface, filesystem or sockets |

Network uses monotonic timers for protocol polling; policy uses them for DNS
expiry. Vsock uses timers for clock updates, system time for guest
clock synchronization, and randomness for the guest seed. Filesystem WIT depends
on clock types for timestamps; that dependency alone does not grant a clock call.

Components except vsock build for `wasm32-unknown-unknown` to avoid implicit WASI
services from the Rust standard library. Vsock targets `wasm32-wasip3` so upstream
Yamux can use the standard monotonic clock. Its WASI imports are checked with the
same authority inventory and linked explicitly. Clock access uses explicit WIT imports
only where protocol timers, DNS expiry or guest clock synchronization require it.

The [component authority inventory](../../docs/component-authority.md) records each
remaining imported function and resource scope. `component_imports` checks every
built component artifact. `component_grants` probes native linkers: only VMM receives VM/vCPU
resources, only vsock receives secure randomness, and device-specific filesystem,
socket and local-client resources remain restricted.

`make verify-wit` checks that the links resolve inside this directory. Component
builds run this check before parsing and compiling the interfaces.

On Windows, enable Developer Mode or use an account with symlink privileges and
clone with `git -c core.symlinks=true clone <repository>`. Windows CI sets
`core.symlinks` before checkout. A checkout that materializes links as text files
is rejected by the link check.
