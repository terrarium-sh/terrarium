# Windows sandboxing

Each worker runs in its own Less-Privileged AppContainer, created per launch with
a unique profile and package SID. A trusted wrapper launches it suspended inside a
single-process job and checks the result before the worker starts.
[Host process sandboxing](sandboxing.md) covers what each role holds.

## Process layout

```text
terra.exe (CLI)             your user, unconfined
└─ terra.exe __supervisor   unconfined; binds published listeners
   ├─ __sandbox_launcher    trusted wrapper: DACL grants, console
   │  │                     relay, guest symlinks
   │  └─ __vm               AppContainer and job; HypervisorPlatform,
   │                        registryRead; granted box files, shares
   └─ __sandbox_launcher    trusted wrapper: opens TCP and UDP
      │                     sockets for the broker
      └─ __network          AppContainer and job, 512-MiB commit
                            limit; internetClient, registryRead

__vm ◄── socket pair ──► __network
__supervisor ── startup channel ──► __network
__network ── socket requests ──► wrapper ── sockets ──► __network
__vm ── symlink requests ──► wrapper
terra.exe (CLI) ── agent and control sockets ──► __vm
```

## Capabilities

| Worker | Capabilities | Files | Networking | Other limits |
| --- | --- | --- | --- | --- |
| VM | `HypervisorPlatform`, `registryRead` | Approved grants | None | Dynamic code allowed for Wasmtime's AOT components |
| Broker | `internetClient`, `registryRead` | Its executable only | Sockets opened by its wrapper, name resolution | 512-MiB commit limit, dynamic code disabled |

The role policies are built in and cannot be overridden.

## Both workers

The job kills the worker when the last job handle closes, permits
no child processes, and blocks desktop, clipboard, global atom and USER-handle
access. Workers get no Win32k system calls, forced and high-entropy ASLR,
permanent strict handle checks, heap termination, module tampering protection,
branch-target isolation and speculative store bypass disable. They load no
legacy extension DLLs, non-system fonts, or images from remote shares or with a
low integrity label, and resolve DLLs from System32 first. Workers are never
attached to a console: console input becomes `NUL`, and console output passes
through a wrapper relay as text with control characters replaced, so a worker
cannot queue keystrokes for the user's shell or send terminal escape sequences.
Before running, each worker must find its AppContainer token with exactly its
role's capabilities, its job, and no reachable console; any other result fails
startup.

## VM grants

The VM's package SID is the only one added to approved file DACLs;
orderly exit removes the grants and deletes the profile. Read-only grants carry
explicit write/delete/permission denies; writable directories omit
`FILE_DELETE_CHILD`. The VM gets no grant on the box directory itself, only on
the files its box configuration names: the root disk, configured volumes and logs
read-write, and box metadata read-only. Grant traversal skips reparse
points, and share roots cannot be reparse points. Filesystem operations resolve
guest paths within the approved share; a launch may grant at most 16,384 objects.

## WHP

The VM's `HypervisorPlatform` capability permits access to Windows
Hypervisor Platform; `registryRead` lets Winsock initialize for inherited IPC.
The VM receives no network capabilities. A WHP failure aborts the launch without
retrying.

## Broker sockets

AppContainer network isolation blocks a container's own
sockets from host loopback, which published listeners and `HOST_LOOPBACK` rules
need, and the broker's token lacks the capability to accept connections on its
own sockets. Its published listeners come from the supervisor. For outbound
traffic the broker asks its wrapper, over an inherited channel, to connect a TCP
socket to a peer its policy approved or for a UDP socket bound to an ephemeral
port; the wrapper completes the connection, within 30 seconds and at most 64 at a
time, and duplicates the socket into the broker. No socket the broker can obtain
is able to listen. The broker has no file grants beyond its
executable, so it cannot read user files, box state or the user's other
processes, and its commit limit bounds memory.

The broker accepts on the listeners the supervisor bound and
opens IPv4 or IPv6 TCP/UDP sockets through its wrapper. It applies destination
policy before requesting them; published listeners claim their ports with
`SO_EXCLUSIVEADDRUSE`, so no other local process can bind the same port. The VM receives no native sockets and uses
the bounded broker IPC protocol for network operations.

## Lifetime

The wrapper watches the supervisor process and stops the worker if
the supervisor exits. Only standard I/O, the IPC sockets, the broker's socket
channel, the VM's symlink channel, approved listeners and run-lock handle are
inherited. If the
wrapper itself is killed, the job still ends the worker, but DACL and profile
cleanup cannot run; profile names are never reused.

## Symlinks

Guest symlinks in host-shared directories are stored the way WSL
stores them (`IO_REPARSE_TAG_LX_SYMLINK`). AppContainer can neither set nor read
any reparse point, so a VM with mounts passes link requests to its wrapper over
an inherited channel. Each request names a share the supervisor validated and a
path beneath it: the wrapper creates links only beneath writable shares, reads
them beneath any of the VM's shares, and does nothing else. Windows never follows
these links, so a guest-planted link cannot redirect host programs; Windows tools
other than WSL see them as files they cannot open. The wrapper refuses absolute
targets, as other hosts do. Windows symlinks already in a share still read as symlinks.

## Limits

No mount, PID or user namespaces and no seccomp. A compromised broker
can request any number of wrapper connections and UDP sockets, so it keeps
outbound host network access, including host loopback, and can receive on its
UDP sockets.

## Validation

The compiled probe runs both workers under these policies, reads each worker's
mitigations back from the kernel, and checks VM grants, WHP access, symlinks
through the wrapper and denied VM networking:

```powershell
$env:TERRA_BIN = (Resolve-Path dist\terra.exe).Path
cargo test -p terra-sandbox --lib windows::tests::native_roles_enforce_vm_grants_and_broker_job -- --ignored
```

Native validation must also show that VM TCP/UDP fails for loopback, private
and public destinations while broker IPC works; that host AF_UNIX paths in
shares give no tunnel; that the VM cannot replace the PID files; and that
killing the supervisor or wrapper at any phase leaves no worker or live socket.
