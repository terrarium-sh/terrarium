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
| vmm | VM lifecycle, vCPU execution, device worker grants and lifecycle events |
| policy | No Terra host interface, filesystem or sockets |

Network uses monotonic timers for protocol polling; policy uses them for DNS
expiry. Vsock uses timers for retries and clock updates, system time for guest
clock synchronization, and randomness for the guest seed. Filesystem WIT depends
on clock types for timestamps; that dependency alone does not grant a clock call.

The current Rust `wasm32-wasip3` artifacts also import WASI CLI and monotonic/system
clocks, including components whose source world does not declare them. Native
linkers must satisfy those imports to load the artifacts. CLI contexts do not
inherit host arguments, environment, working directory or stdio. Removing these
toolchain imports requires changing the component build/runtime, not unlinking a
WIT dependency.

`component_imports` pins the exact interface-name set of all eight built
components. `component_grants` probes native linkers: only VMM receives VM/vCPU
resources, only vsock receives secure randomness, and device-specific filesystem,
socket and local-client resources remain restricted.

`make verify-wit` checks that the links resolve inside this directory. Component
builds run this check before parsing and compiling the interfaces.

On Windows, enable Developer Mode or use an account with symlink privileges and
clone with `git -c core.symlinks=true clone <repository>`. Windows CI sets
`core.symlinks` before checkout. A checkout that materializes links as text files
is rejected by the link check.
