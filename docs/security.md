# Security model

Terra runs a workload in a hardware-virtualized VM. The VM boundary is intended
to protect the host from a hostile guest, subject to the trusted computing base
and limits below. Linux uses KVM, macOS uses Hypervisor.framework, and Windows
uses WHP. Current-build hardware acceptance remains tracked in
[todo.md](todo.md); earlier Linux results do not validate every later change.

This document describes the boundary Terra implements. It is not an assurance
against flaws in the host kernel, hypervisor, Wasmtime, WASI, native runtime,
or the trusted build pipeline.

## Trust and authority

Treat the guest kernel, every process in the guest (including guest root),
guest-controlled device requests, network peers, and Wasm device code as
hostile. Trust the host operating system and identity that start Terra, the
recipe chosen by the operator, and the build pipeline that produces Terra and
its embedded components.

A recipe is an authorization decision. Review it before `terra setup`,
especially when it comes from another repository. It can grant host
directories, network destinations, environment values, published ports, and
guest-root hooks.

The shipped binary embeds precompiled Wasmtime components. Deserializing an
AOT component is trusted native-code loading, so those artifacts must come from
the matching Terra build; guest or network input must never supply them.

### Recipe storage

Ideally, keep source recipes and the `terra.yaml` manifest outside every
guest-writable share. Share only the workload's files, or use a read-only
mount where the guest needs to read recipes. A separate read-only mount does
not protect a recipe that the guest can also reach through a writable share.

Terra permits recipes in writable shares when a workflow requires it, but a
guest can create or modify those recipes, or change which recipe a manifest
selects. Review both files before approving setup; `--trust-recipe` is the
operator's approval of their contents.

The guest-authorship check uses currently pinned writable shares, without a
history of removed grants. Removing a share and running setup removes its
mount pin, but does not delete or make trustworthy any files the guest left
on the host. If you later select such a recipe, especially for a new box,
Terra may no longer warn that a guest could have authored it. This remains
possible after the guest has shut down. Review files from former shares as
untrusted input rather than relying on the absence of a warning.

## Recipe grants

| Recipe feature | Authority it grants |
| --- | --- |
| `mounts` | Access to the selected host directory. A writable mount permits creation, modification, and deletion in that directory; `readonly` is enforced by the host-side directory capability. |
| `network.allow` | Outbound access to the allowed destination and port. An explicit `HOST_LOOPBACK` grant can reach services on the Terra host. |
| `network.hosts` | Local DNS records; a record alone does not authorize a connection. Add a matching `allow` rule. |
| `network.mode: unrestricted-public` | Public egress without individual rules, including public addresses on a LAN. IPs collected from host interfaces at VM startup, including public IPs, and blocked private, link-local, and cloud-metadata ranges require explicit grants. |
| `network.ports` | A guest listener published on host loopback. |
| `env` and `env_file` | Values delivered to guest hooks and workload processes. Secrets delivered to a guest may be copied or persisted by it. |
| `hooks`, `sudo`, and `terra exec --root` | Guest-root authority inside that box only. |
| `terra sync` | A host-initiated synchronization of files and directories. The operator chooses the host path and authorizes guest input or output. |

Filtering uses destination addresses, not network location or the identity of
machines behind them. A public address that forwards to the host through NAT
may remain reachable if it is not among the collected host interface addresses.
The host address list is a startup snapshot, not a live inventory.

The default network mode is an empty allowlist. An allowed network service is
trusted for every action a guest can take over that connection; destination
filtering cannot constrain the application protocol. `network.ports` does not
publish a service to a non-loopback host address.

The egress floor checks the embedded IPv4 destination in the NAT64 well-known
prefix `64:ff9b::/96`. Site-specific translation prefixes are not inferred from
host routing; hosts using them need equivalent destination filtering at the
translator.

Mounts are opened as directory capabilities and exposed to their filesystem
component as a WASI preopen. A guest path or symlink does not create a new host
directory grant. Grant only the tree the workload needs. In particular, do not
mount device directories, broad home directories, or other unrelated host
trees.

`env_file` follows the operator-selected host path. `sync` validates guest
manifest paths and link targets and checks destination ancestors for symlinks
before accessing entries. These checks assume the host destination is not
concurrently modified, including through a guest-writable share; they do not
protect against an ancestor being replaced between a check and an operation.
Metadata-only downloads reject multiply linked files to avoid changing another
path's inode permissions or timestamps. `--delete` authorizes removal of
destination extras within that tree. These operations are distinct from a WASI
mount capability.

## Runtime boundary

Terra creates a separate Wasmtime store, linear memory, resource table and host
state for each VMM and device component, with an explicitly restricted linker.
This is a software fault isolation security boundary: Wasmtime confines component
memory accesses and control flow, while native effects require explicitly
granted functions, resources or stream endpoints. Native code owns VM creation,
guest-RAM mappings, hypervisor handles,
host I/O, and the checks that grant filesystem and network authority.
Guest-memory, block-I/O, and reclaim requests are range- and overflow-checked
before native access. Block disks are opened as fixed-capacity grants; guest
writes cannot extend their initial extent. The filesystem component receives a
scoped directory preopen only when a mount is configured. Network socket and
name-resolution operations are checked against the box policy before the host
operation proceeds. Device components do not receive arbitrary host filesystem
or hypervisor handles.

Native preparation fixes the machine resources before a separate boot store
parses the kernel. Native code validates its bounded writes and one-time result,
then destroys the boot store before starting the VMM. Only the VMM receives
opaque vCPU resources; device components cannot create or select a hypervisor.

| Component | Scoped authority beyond runtime support |
| --- | --- |
| VMM | Scoped VM/vCPU lifecycle resources and access to the MMIO client. |
| MMIO | Supplied device mappings and explicitly connected request/reply streams; no imported host functions. |
| Interrupt controller | Supplied interrupt topology and value-based operations; no imported host functions. |
| Block | Its VM's RAM, assigned interrupt and one fixed-capacity backing disk. |
| Filesystem | Its VM's RAM, assigned interrupt and one directory preopen. |
| Network | Its VM's RAM, assigned interrupt, policy-controlled WASI sockets/DNS, and warnings in the capped host log. |
| Memory | Its VM's RAM, assigned interrupt and bounded reclamation of that RAM. |
| Vsock | Its VM's RAM, assigned interrupt, supplied local service streams and secure randomness. |
| Policy | Immutable policy configuration and host-submitted resolver results; no guest RAM, filesystem or sockets. |

The MMIO bridge and software interrupt controller each run in their own
restricted store with an empty host-function linker. They have no host memory,
WASI, filesystem, network, clock, random, VM, vCPU, or guest-RAM capability.
The MMIO adapter accepts a reply only for the mapped device and access range.
The controller adapter accepts only granted GSI lines and valid x86 interrupt
vectors and destinations before injecting an interrupt. These checks make the
split a security measure against a compromised service component: it cannot
directly access the host or apply an unchecked native effect. Device connections
can still indirectly cause the particular host I/O authorized for that device.

This SFI boundary is within one host process. It relies on Wasmtime's Wasm
memory and control-flow enforcement, the correctness of the registered host
functions, and the native adapters. It is therefore not a defense against a
Wasmtime, native-runtime, hypervisor, or host-kernel vulnerability, and it does
not isolate components into separate operating-system processes.

Components inherit no host environment, arguments or standard streams. Devices
can read and corrupt their own VM's RAM: component isolation protects the host
and other boxes, not the guest from its devices. A directory preopen authorizes
its contents even when a compromised filesystem component bypasses FUSE parsing;
Wasm-only special-file filters are not a host restriction.

The policy sidecar has bounded input and per-call fuel. Traps fail authorization
closed. Device stores use epoch interruption, and production shared memory is
disabled. Learned DNS grants expire for new connections after 60 seconds unless
renewed; existing connections continue.

Component setup and device requests have bounded runtime interfaces and
deadlines. These controls limit malformed requests and waiting work; they do
not make host I/O interruptible or turn component failures into durable
transactions.

Guest diagnostic events are limited to 64 KiB, enter a bounded queue, and are
written through an 8 MiB per-file cap. This prevents diagnostic floods from
growing the host log without bound; it is not a general storage quota.

Component memory has independent per-store Wasm linear-memory limits, with
a default and minimum configurable ceiling of 16 MiB. There is no combined
component memory cap. Those limits do not bound guest RAM,
native/WASI allocations, kernel socket memory, CPU time, disk use in writable
shares, or bandwidth. Terra's per-home admission accounting reserves the maximum
configured component footprint plus guest RAM and native headroom. This is not
a host-wide resource quota. Apply operating-system limits or a dedicated host
when hard resource isolation is required.

Native resource tables use Wasmtime's default capacity except where a device
sets its own limit, such as filesystem descriptors. Network flow admission
bounds concurrent socket work; Wasm memory ceilings do not bound native table
allocations or the size of their entries.

Terra keeps its box state, recipes, images, logs, and local control sockets
under `~/.terra` with owner-only permissions where the platform supports them.
`terra setup` refuses to run as host root unless `TERRA_ALLOW_ROOT=1` is set.
Running Terra as host root expands the impact of a boundary failure.

## Outside the boundary

- A writable mount is deliberately shared storage, not a safe place to accept
  untrusted data for host-side execution or parsing. Treat guest-written files
  as untrusted before using them on the host.
- Concurrent host-local mutation of a mounted tree, and host interpretation of
  guest-written share contents, are outside this boundary.
- Guest users, guest root, `sudo`, and lifecycle hooks protect only the guest
  filesystem. They do not grant host root, but a recipe can use them to change
  everything in the guest.
- Attached workload output is guest-controlled terminal input. A hostile guest
  can emit terminal control sequences, so use a terminal policy appropriate for
  untrusted output.
- Component isolation is a host-security boundary for component code within its
  trusted computing base. It does not protect against a defect in Wasmtime,
  WASI, native adapters, or the hypervisor.
- Cancellation and timeouts do not roll back a host write or forcibly interrupt
  an operating-system I/O operation already in progress.
- Terra does not provide a hard defense against denial of service, hardware
  side channels, or a compromise of the host OS, hypervisor, native runtime,
  Wasmtime, WASI, or trusted artifacts.

For the configuration syntax and defaults, see the [recipe reference](recipe.md).
To report a vulnerability, follow the [security policy](../SECURITY.md).
