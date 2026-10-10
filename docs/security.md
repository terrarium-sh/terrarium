# Security model

Terra runs a workload in a hardware-virtualized VM (KVM on Linux,
Hypervisor.framework on macOS, WHP on Windows) to protect the host from a
hostile guest, within the trusted computing base and limits below. Only Linux
has passed native acceptance; macOS and Windows gates are open in
[todo.md](todo.md).

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
| `network.enabled: false` | Guest-local networking with no broker or external network connections. Agent control remains available. |
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

Each VMM and device component runs in its own Wasmtime store with its own
linear memory, resource table and an explicitly restricted linker. Wasmtime
confines each component's memory and control flow; native effects need an
explicitly granted function, resource or stream. Native code owns VM creation,
guest-RAM mappings, hypervisor handles and host I/O, and range- and
overflow-checks every guest-memory, block and reclaim request before acting on
it. Block disks are fixed-capacity grants that guest writes cannot extend.
[Component authority](component-authority.md) lists what each component may
import and why.

A separate boot store parses the kernel after native preparation fixes the
machine resources. Native code validates every planned kernel segment and
boot-data write, then destroys the boot store before the VMM starts. Only the
VMM receives vCPU resources; native MMIO routing validates mappings, access
ranges, reply sequences and deadlines, and the interrupt adapter accepts only
granted lines and valid x86 vectors and destinations.

The combined vsock device/network frontend validates transport packets, opening
handshakes and UDP/control frames, then submits bounded socket requests to the
separate broker, which authorizes each one even if the frontend is compromised.
Device reset disconnects every connection; losing the broker or network control
retires networking while agent control stays available. The
[network transport](../README.dev.md#network-transport) defines these streams.

The default [host VM launcher](vm-launchers.md) runs the VM and the broker as
separately confined processes; [host process sandboxing](sandboxing.md)
describes each role, its grants and its filters. Without a generated policy
bundle, the built-in fallback filters allow broader syscall access within the
same namespace and filesystem boundaries; `install.sh` installs the release
bundle. Direct and custom launchers are trusted host code with their own
boundaries; a successful launch does not establish confinement.

Components inherit no host environment, arguments or standard streams. Devices
can read and corrupt their own VM's RAM: component isolation protects the host
and other boxes, not the guest from its devices. A directory preopen authorizes
its contents even when a compromised filesystem component bypasses FUSE parsing;
Wasm-only special-file filters are not a host restriction.

The CLI validates network policies with the broker's own policy core. Explicit
configuration, rule, name, resolver and learned-address bounds constrain policy
work, and authorization errors fail closed. Device stores use epoch
interruption, and production shared memory is disabled. Learned DNS grants expire for new connections after 60 seconds unless
renewed; existing connections continue.

Component setup and device requests have bounded runtime interfaces and
deadlines. These controls limit malformed requests and waiting work; they do
not make host I/O interruptible or turn component failures into durable
transactions.

Guest diagnostic events are size-limited, enter a bounded queue, and are
written through an 8 MiB per-file cap. This prevents diagnostic floods from
growing the host log without bound; it is not a general storage quota.

Component memory has independent per-store Wasm linear-memory limits. The
default is 16 MiB, raised to 216 MiB for the combined network frontend so its
1024-flow table fits; configurable ceilings require at least 16 MiB. There is no combined
component memory cap. Those limits do not bound guest RAM,
native/WASI allocations, kernel socket memory, CPU time, disk use in writable
shares, or bandwidth. Operators control aggregate VM resource budgets.
Apply operating-system limits or a dedicated host
when hard resource isolation is required.

Native resource tables use Wasmtime's default capacity except where a device
sets its own limit, such as filesystem descriptors. The combined frontend caps
its resource table using broker resource, listener and pending-operation limits.
These entry counts and network flow admission bound concurrent socket work;
Wasm memory ceilings do not bound native allocations or entry sizes.

Terra keeps its box state, recipes, images, logs, and local control sockets
under `~/.terra` with owner-only permissions where the platform supports them.
`terra setup` refuses to run as host root unless `TERRA_ALLOW_ROOT=1` is set.
Running Terra as host root expands the impact of a boundary failure.

### Network policy limits

In the confined Linux launch, the broker enforces recipe network rules even if
the VM process is compromised. Broker requests are untrusted, bounded, and
validated independently. Only broker-controlled resolution establishes learned
address grants. TCP connections retain established-stream semantics; UDP
rechecks authorization on send and receive as DNS-derived grants expire.

Each broker operation is one flow-controlled stream, so a TCP upload buffers
at most one stream window ahead of the socket. The broker writes upload bytes in
order and acknowledges a half-close only after every earlier byte is written.
Dropping the stream aborts the flow and closes the socket.

The broker's native policy engine is trusted code. A native broker compromise
can bypass its in-process destination rules and use networking allowed by its OS
sandbox. Host-loopback and LAN services may expose privileged APIs or their own
vulnerabilities. Independent host network controls can further restrict broker
authority. Direct launches and custom launchers without equivalent isolation
also allow native VM code to bypass component-level policy using host sockets.
On Windows, the `restricted_token_job` mode is weaker; see
[sandboxing](sandboxing.md#windows).

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
- Component isolation runs inside one host process. It does not protect against
  a defect in Wasmtime, WASI, the native adapters, the hypervisor or the host
  kernel.
- Cancellation and timeouts do not roll back a host write or forcibly interrupt
  an operating-system I/O operation already in progress.
- Terra does not provide a hard defense against denial of service, hardware
  side channels, or a compromise of the host OS, hypervisor, native runtime,
  Wasmtime, WASI, or trusted artifacts.

For the configuration syntax and defaults, see the [recipe reference](recipe.md).
To report a vulnerability, follow the [security policy](../SECURITY.md).
