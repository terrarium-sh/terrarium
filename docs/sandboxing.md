# Host process sandboxing

Terra splits each box into a trusted supervisor and confined workers, then
confines each worker with the host platform's own mechanism. Every box runs
in this built-in sandbox; there is no unconfined launch, and a failed sandbox
launch stops the box. The per-platform pages describe each mechanism and draw
its process layout:

- [Linux](sandboxing-linux.md): Bubblewrap namespaces and seccomp filters.
- [macOS](sandboxing-macos.md): App Sandbox entitlements on signed worker copies.
- [Windows](sandboxing-windows.md): Less-Privileged AppContainers and jobs.

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
[network policy limits](security.md#network-policy-limits). Local-only boxes
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
