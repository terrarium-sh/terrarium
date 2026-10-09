# Host process sandboxing

Terra splits each box into a trusted supervisor and confined workers, then
confines each worker with the host platform's own mechanism. `vm.init: bwrap`
(the default) selects this built-in sandbox; see [host VM launchers](vm-launchers.md)
for configuration, custom launchers and policy generation. A failed sandbox
launch stops the box; there is no automatic fallback to an unconfined launch.

| Role | Holds | Never receives |
| --- | --- | --- |
| Supervisor | Box lock, configuration, worker lifetime, trusted PID files | Guest RAM or network packet payloads |
| VM worker | Guest RAM, disks, shares, the hypervisor, Wasm components, broker IPC | Host network sockets |
| Network broker | External TCP/UDP sockets, resolution, published listeners, native policy engine | VM runtime handles or RAM through Terra's IPC |

Socket descriptors never cross the VM-to-broker channel: the VM receives bounded data
and opaque resource handles, and the broker authorizes every operation even if
the VM's frontend is compromised. A compromised broker still holds whatever
network access its OS sandbox allows; see
[network policy limits](security.md#network-policy-limits). Local-only boxes
(`network.enabled: false`) run no broker.

No platform sandbox supplies hard CPU, memory, disk or bandwidth quotas, except
the Windows broker's commit limit below.

## Linux

The supervisor starts the VM worker and, with networking enabled, the broker
under Bubblewrap.

- Both workers get separate mount, user, PID, IPC and UTS namespaces and drop
  all capabilities. The VM also gets a private network namespace, so its native
  sockets cannot reach host networking; the broker keeps the host network
  namespace.
- Each worker installs its own seccomp filter after namespace setup, and the
  supervisor installs a separate lifecycle filter. Filters are generated from
  traced self-tests and reviewed supplements (`scripts/seccomp/seccomp-supplements.json`).
- Workers stay in the host session, so the built-in filters and every generated
  bundle deny the `TIOCSTI` and `TIOCLINUX` terminal-injection ioctls.
- The broker shares the host network namespace, where abstract Unix sockets
  (such as an X11 display) and host netlink live. Its filters allow only IPv4
  and IPv6 sockets; the supervisor reads host interface addresses for it.
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

The VM runs in AppContainer. The network broker uses a restricted token outside
AppContainer. Both workers use explicit inherited handles and jobs.

| Worker | Default token | Networking | Other limits |
| --- | --- | --- | --- |
| VM | Less-Privileged AppContainer with `HypervisorPlatform` and `registryRead` | None | Approved file grants, local IPC, single-process job, Win32k disabled |
| Broker | Restricted token; privileges removed and Administrators deny-only | Native TCP/UDP and name resolution | 512-MiB commit limit, single-process job, Win32k and dynamic code disabled |

**VM grants.** The VM launch creates a unique AppContainer profile and package SID,
adds only that SID to approved file DACLs, removes the grants on orderly exit and
deletes the profile. Read-only grants carry explicit write/delete/permission
denies; writable directories omit `FILE_DELETE_CHILD`. Box metadata stays
read-only. Grant traversal skips reparse points, and share roots cannot be reparse
points. Filesystem operations resolve guest paths within the approved share;
a launch may grant at most 16,384 objects.

The broker has the user's ordinary file access. Its restricted token and job
limit privileges and process lifetime, but do not isolate host files.

**Lifetime.** A trusted wrapper creates each worker suspended inside a
single-process job that kills it when the last job handle closes. The wrapper
watches the supervisor process and stops the worker if the supervisor exits.
Only standard I/O, the IPC socket, the VM's approved listeners and its run-lock
handle are inherited. If the wrapper itself is killed, the job still ends the
worker, but DACL and profile cleanup cannot run; profile names are never reused.

**WHP.** The VM's `HypervisorPlatform` capability permits access to Windows
Hypervisor Platform; `registryRead` lets Winsock initialize for inherited IPC.
The VM receives no network capabilities. A WHP failure aborts the launch without
retrying. An administrator may select `restricted_token_job` for the VM, which removes
privileges and makes Administrators deny-only but keeps the job, Win32k denial,
child-process denial and handle allowlist. **This mode does not deny native VM
sockets and imposes no AppContainer file or process isolation**: a compromised
VM keeps the user's access. Terra logs this and changes no firewall settings.

Policy overrides live in a directory set by `vm.bwrap.policy`, holding
`supervisor.sandbox.json`, `vm.sandbox.json` and `network.sandbox.json`. Unknown
fields, wrong roles and unsupported versions are rejected, and Linux seccomp files
are not accepted.

```json
{
  "schema_version": 1,
  "role": "vm",
  "mode": "restricted_token_job",
  "less_privileged": false,
  "memory_limit_bytes": 0
}
```

Defaults: supervisor `supervisor`/not less-privileged; VM `app_container`,
less-privileged, no memory limit; broker `restricted_token_job`,
536,870,912-byte limit. Broker AppContainer mode is unsupported.
`less_privileged: false` with VM `app_container` selects regular AppContainer
and its broader baseline access.

**Networking.** The broker creates published listeners from the configured
grants and opens IPv4 or IPv6 TCP/UDP sockets directly. It applies destination
policy before using them. The VM receives no native sockets and uses the
bounded broker IPC protocol for network operations.

**Limits.** No mount, PID or user namespaces and no seccomp.

AppContainer cannot create Windows symbolic links, even with Developer Mode
enabled. Guest symlink creation therefore fails in host-shared directories;
symlinks inside the guest's Linux disks continue to work. Folder mounts do not
require symlinks. The bundled self-test reports this limitation and continues
checking the other shared-filesystem operations.

Native validation must show that VM TCP/UDP fails for loopback, private and public
destinations while broker IPC works; that host AF_UNIX paths in shares give no
tunnel; that the broker can use native loopback sockets; that the VM cannot replace
the PID files; that no stray handles reach workers; and that killing the
supervisor or wrapper at any phase leaves no worker or live socket. Isolation
VM isolation tests must fail when the VM selects `restricted_token_job` mode. The compiled grant probe:

```powershell
$env:TERRA_BIN = (Resolve-Path target\debug\terra.exe).Path
cargo test -p terra-sandbox --lib windows::tests::native_roles_enforce_vm_grants_and_broker_job -- --ignored
```
