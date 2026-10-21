# Host process sandboxing

Terra splits each box into a trusted supervisor and confined workers, then
confines each worker with the host platform's own mechanism. Every box runs
in this built-in sandbox; there is no unconfined launch, and a failed sandbox
launch stops the box. The per-platform pages describe each mechanism and draw
its process layout:

- [Linux](sandboxing-linux.md): Bubblewrap namespaces and seccomp filters.
- [macOS](sandboxing-macos.md): Seatbelt profiles applied by a trusted launcher.
- [Windows](sandboxing-windows.md): Less-Privileged AppContainers and jobs.

## Strictness per platform

What an attacker gets after compromising a worker's native code.

| | Linux | macOS | Windows |
| --- | --- | --- | --- |
| **Mechanism** | Namespaces + seccomp | Seatbelt profile | Less-Privileged AppContainer + job |
| **Syscall filter** | Generated allowlist per role | None | Win32k calls blocked |
| **Supervisor** | Seccomp-filtered | Unconfined | Unconfined |
| ***VM worker can…*** | | | |
| Reach the network | No: own network namespace | No | No |
| Read files beyond its grants | No | Apple's `system.sb` baseline | System files open to all AppContainers |
| Start another program | No: no `execve` | No | No: job allows no children |
| ***Broker can…*** | | | |
| Connect out | Any address, host loopback included | Any address, host loopback included | Any address, through its wrapper |
| Open a TCP listener | No | No | No |
| Read files | Resolver files and `/proc`, including the host's `/proc/net` | Resolver files only | Its own executable only |
| Create a VM | No: no `/dev` | **Yes**: shares the hypervisor entitlement | No: no hypervisor capability |
| Memory cap | None | None | 512 MiB commit |

Linux is the strictest: every role, the supervisor included, runs under a
syscall allowlist. The supervisor never handles guest RAM or packets, so leaving
it unconfined on macOS and Windows matters only if a worker escapes first.
Windows adds a job and exploit mitigations but filters no syscalls. macOS rests on a single Seatbelt profile per worker, built on a
private, deprecated Apple interface. On every platform a compromised broker
keeps outbound network access, so use a host firewall when that matters.
Native validation on macOS and Windows is still pending; see
[todo.md](todo.md).

## Processes

Every platform runs the same processes; only the confinement around the two
workers differs.

```text
terra (CLI)            your user; exits once a detached box is ready
└─ supervisor          box lifetime, run lock, published listeners
   ├─ VM worker        sandboxed; guest RAM, disks, shares, devices
   └─ network broker   sandboxed; host sockets, resolution, egress

VM worker ◄── IPC ──► network broker   bounded requests, no sockets
terra (CLI) ── agent and control sockets ──► VM worker
```

| Role | Holds | Never receives |
| --- | --- | --- |
| Supervisor | Box lock, configuration, worker lifetime, trusted PID files, published listener binding | Guest RAM or network packet payloads |
| VM worker | Guest RAM, disks, shares, the hypervisor, Wasm components, broker IPC | Host network sockets |
| Network broker | External TCP/UDP sockets, resolution, handed-over published listeners, native policy engine | VM runtime handles or RAM through Terra's IPC, or authority to listen |

## Network broker

Socket descriptors never cross the VM-to-broker channel: the VM receives bounded data
and opaque resource handles, and the broker authorizes every operation even if
the VM's frontend is compromised. A compromised broker still holds whatever
network access its OS sandbox allows; see
[network policy limits](security.md#network). Local-only boxes
(`network.enabled: false`) run no broker.

The supervisor binds every published listener on host loopback before it starts
the broker or installs its own sandbox, and passes them on the broker's startup
channel (Unix descriptor passing, Windows socket duplication). The broker checks
that each matches its grant and only accepts on them; it never binds a listener
itself.

## Policies

Each role's policy is built into the executable; no setting, file or
environment variable changes it at run time. On Linux the policy includes
syscall allowlists generated from the code; see
[host sandbox policy](sandbox-policy.md).

No platform sandbox supplies hard CPU, memory, disk or bandwidth quotas, except
the Windows broker's commit limit.
