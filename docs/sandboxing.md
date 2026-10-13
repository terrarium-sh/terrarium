# Host process sandboxing

Terra splits each box into a trusted supervisor and confined workers, then
confines each worker with the host platform's own mechanism. `vm.init: sandbox`
(the default) selects this built-in sandbox; see [host VM launchers](vm-launchers.md)
for configuration and policy generation. A failed sandbox
launch stops the box; there is no automatic fallback to an unconfined launch.

| Role | Holds | Never receives |
| --- | --- | --- |
| Supervisor | Box lock, configuration, worker lifetime, trusted PID files, published listener binding | Guest RAM or network packet payloads |
| VM worker | Guest RAM, disks, shares, the hypervisor, Wasm components, broker IPC | Host network sockets |
| Network broker | External TCP/UDP sockets, resolution, handed-over published listeners, native policy engine | VM runtime handles or RAM through Terra's IPC, or authority to listen |

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

No platform sandbox supplies hard CPU, memory, disk or bandwidth quotas, except
the Windows broker's commit limit below.

## Linux

The supervisor starts the VM worker and, with networking enabled, the broker
under Bubblewrap.

- Both workers get separate mount, user, PID, IPC and UTS namespaces and drop
  all capabilities. The VM also gets a private network namespace, so its native
  sockets cannot reach host networking; the broker keeps the host network
  namespace.
- Bubblewrap installs each worker's seccomp filters after namespace setup and
  before exec: a permanent role filter plus the selected bundle's filter. The
  supervisor installs its own lifecycle filter. Bundles are generated from
  traced self-tests and reviewed supplements (`scripts/seccomp/seccomp-supplements.json`).
- The broker gets no `/dev` device nodes and no `/tmp`.
- Workers stay in the host session, so the built-in filters and every generated
  bundle deny the `TIOCSTI` and `TIOCLINUX` terminal-injection ioctls.
- The broker shares the host network namespace, where abstract Unix sockets
  (such as an X11 display) and host netlink live. Its filters allow only IPv4
  and IPv6 sockets and deny `listen`; the supervisor reads host interface
  addresses for it.
- The launcher clears the inherited environment and forwards only diagnostic and
  worker metadata. Guest environment grants travel in the boot plan; broker
  policy and listener grants arrive on a supervisor-controlled startup channel
  that VM requests cannot alter.
- `host.pid` names the VM in the host PID namespace and `supervisor.pid` the
  process owning box lifetime. Workers cannot rewrite these through their
  filesystem grants. Stop and failed startup clean up the whole process tree.
- The VM holds a duplicate run-lock descriptor, so supervisor death cannot let
  another boot reuse the disks before the old VM exits. The lock is cooperative:
  compromised native VM code can unlock its own box.
- Broker failure after startup leaves the VM and agent running with networking
  unavailable; there is no reconnect or fallback to direct networking.

The built-in launcher targets the statically linked musl release executable.
Native KVM and negative enforcement tests are required per architecture.

## macOS

Each worker runs as its own App Sandbox executable; the supervisor stays outside
App Sandbox.

| Worker | Entitlements |
| --- | --- |
| VM | Hypervisor.framework, approved VM files and shares, inherited IPC; no network client or server entitlement |
| Broker | Outgoing and incoming connections, resolver files, inherited IPC; no hypervisor, disks or shares |

The broker keeps the incoming-connections entitlement to accept on its
handed-over listeners, so App Sandbox alone does not stop it from listening.

**Signing.** Each launch copies the executable into a private `.app` bundle under
`~/.terra`, writes role entitlements and signs it with `/usr/bin/codesign`. The
bundle identifier hashes the executable and grants, so differing roles and grants
never share an App Sandbox container. Signatures are ad hoc by default; set
`TERRA_MACOS_SIGN_IDENTITY` to use a keychain identity. Signing failure stops
startup. Developer ID signing and notarization of the shipped CLI are separate
distribution steps. Hardened Runtime is on for both roles; only the VM gets the
unsigned executable-memory exception that Wasmtime's AOT code loading needs.

**Activation check.** Before initializing, each worker must fail to open a private
canary file outside its grants, and the VM must fail IPv4 and IPv6 loopback TCP
connects and listens. Any other outcome fails startup and reaps the worker;
entitlement presence alone is not trusted.

**Files.** Grants use absolute-path file exceptions, which are additive: a
read-only grant inside a writable grant is rejected, since App Sandbox cannot
express a nested read-only bind. The VM gets the box directory read-only plus
specific writable disk, diagnostics and `runtime-logs/` paths. File exceptions
do not grant Unix-socket authority, so the supervisor prebinds the agent and stop
listeners and passes them to the VM as descriptors.

**Limits.** App Sandbox keeps a platform baseline (system resources, world-readable
files, its container, temporary storage). There are no namespaces, seccomp or
mount remapping, and Linux seccomp overrides are rejected.

Native acceptance on Apple Silicon macOS 15+:

```sh
cargo test -p terra-sandbox --lib macos -- --ignored --test-threads=1
terra self-test
```

Then run the packaged VM tests and exercise guest TCP, UDP, DNS, published
listeners, shares, stop, detached lifetime and abrupt supervisor or broker death.

## Windows

Each worker runs in its own Less-Privileged AppContainer, created per launch with
a unique profile and package SID. A trusted wrapper launches it suspended inside a
single-process job and checks the result before the worker starts.

| Worker | Capabilities | Files | Networking | Other limits |
| --- | --- | --- | --- | --- |
| VM | `HypervisorPlatform`, `registryRead` | Approved grants | None | Dynamic code allowed for Wasmtime's AOT components |
| Broker | `internetClient`, `registryRead` | Its executable only | Sockets opened by its wrapper, name resolution | 512-MiB commit limit, dynamic code disabled |

**Both workers.** The job kills the worker when the last job handle closes, permits
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

**VM grants.** The VM's package SID is the only one added to approved file DACLs;
orderly exit removes the grants and deletes the profile. Read-only grants carry
explicit write/delete/permission denies; writable directories omit
`FILE_DELETE_CHILD`. The VM gets no grant on the box directory itself, only on
the files its box configuration names: the root disk, configured volumes and logs
read-write, and box metadata read-only. Grant traversal skips reparse
points, and share roots cannot be reparse points. Filesystem operations resolve
guest paths within the approved share; a launch may grant at most 16,384 objects.

**Broker sockets.** AppContainer network isolation blocks a container's own
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

**Lifetime.** The wrapper watches the supervisor process and stops the worker if
the supervisor exits. Only standard I/O, the IPC sockets, the broker's socket
channel, the VM's symlink channel, approved listeners and run-lock handle are
inherited. If the
wrapper itself is killed, the job still ends the worker, but DACL and profile
cleanup cannot run; profile names are never reused.

**WHP.** The VM's `HypervisorPlatform` capability permits access to Windows
Hypervisor Platform; `registryRead` lets Winsock initialize for inherited IPC.
The VM receives no network capabilities. A WHP failure aborts the launch without
retrying.

The role policies are built in and cannot be overridden; `vm.sandbox.policy`
is refused on Windows. A host that cannot run them needs `vm.init: direct` or
a custom launcher ([host VM launchers](vm-launchers.md)).

**Networking.** The broker accepts on the listeners the supervisor bound and
opens IPv4 or IPv6 TCP/UDP sockets through its wrapper. It applies destination
policy before requesting them; published listeners claim their ports with
`SO_EXCLUSIVEADDRUSE`, so no other local process can bind the same port. The VM receives no native sockets and uses
the bounded broker IPC protocol for network operations.

**Limits.** No mount, PID or user namespaces and no seccomp. A compromised broker
can request any number of wrapper connections and UDP sockets, so it keeps
outbound host network access, including host loopback, and can receive on its
UDP sockets.

**Symlinks.** Guest symlinks in host-shared directories are stored the way WSL
stores them (`IO_REPARSE_TAG_LX_SYMLINK`). AppContainer can neither set nor read
any reparse point, so a VM with mounts passes link requests to its wrapper over
an inherited channel. Each request names a share the supervisor validated and a
path beneath it: the wrapper creates links only beneath writable shares, reads
them beneath any of the VM's shares, and does nothing else. Windows never follows
these links, so a guest-planted link cannot redirect host programs; Windows tools
other than WSL see them as files they cannot open. The wrapper refuses absolute
targets, as other hosts do. Windows symlinks already in a share still read as symlinks.

`terra self-test` runs both workers under these policies and checks that the
broker cannot read a VM file grant, that its own sockets cannot reach host
loopback while wrapper connections can, that no wrapper socket can listen, and
that it resolves names; its box stage serves published ports through
supervisor-bound listeners. The compiled probe additionally reads each worker's mitigations back
from the kernel and checks VM grants, WHP access, symlinks through the wrapper
and denied VM networking:

```powershell
$env:TERRA_BIN = (Resolve-Path dist\terra.exe).Path
cargo test -p terra-sandbox --lib windows::tests::native_roles_enforce_vm_grants_and_broker_job -- --ignored
```

Native validation must also show that VM TCP/UDP fails for loopback, private
and public destinations while broker IPC works; that host AF_UNIX paths in
shares give no tunnel; that the VM cannot replace the PID files; and that
killing the supervisor or wrapper at any phase leaves no worker or live socket.
