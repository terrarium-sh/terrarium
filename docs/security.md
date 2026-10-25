# Security model

Terra protects the host from a hostile guest by running each box in a
hardware-virtualized VM: KVM on Linux, Hypervisor.framework on macOS, WHP on
Windows. This page says what Terra trusts, what a recipe grants, and where the
protection stops. Open hardening work is in [todo.md](todo.md).

## What is trusted

**Hostile:** the guest kernel, every guest process including guest root,
device requests from the guest, network peers, and the Wasm device code.

**Trusted:** the host OS, the user who runs Terra, the recipe that user
chooses, and the build that produced Terra and its embedded components.

The embedded Wasm components are precompiled native code. Loading them means
running that code, so they must come from the matching Terra build, never from
the guest or the network.

## A recipe is a permission

Review a recipe before `terra setup`, especially one from another repository.
It decides what the box can reach:

| Recipe feature | What it grants |
| --- | --- |
| `mounts` | Access to that host directory. A writable mount lets the guest create, change and delete files there; `readonly` is enforced on the host. |
| `network.allow` | Outbound access to that destination and port. `HOST_LOOPBACK` reaches services on the Terra host. |
| `network.hosts` | DNS records only. A connection still needs a matching `allow` rule. |
| `network.mode: unrestricted-public` | Any public address, including public addresses on your LAN. Host interface IPs and private, link-local and cloud-metadata ranges still need explicit rules. |
| `network.ports` | A guest listener published on host loopback only. |
| `network.enabled: false` | No external network and no broker. Terra can still control the box. |
| `env`, `env_file` | Values passed to hooks and the workload. A guest can copy or keep any secret it receives. |
| `hooks`, `sudo`, `terra exec --root` | Root inside that box only. |
| `terra sync` | A file copy you start, between a host path you choose and the guest. |

### Where recipes live

Keep recipes and `terra.yaml` out of writable shares. A guest that can write a
recipe, or the manifest that picks one, can grant itself more. A read-only
mount of the same file does not help if a writable share also reaches it.

If your workflow needs recipes in a writable share, Terra allows it but warns.
`--trust-recipe` means you reviewed both files.

The warning only checks shares that are pinned now. Removing a share does not
make the files the guest left there safe, and Terra will no longer warn about
them. Treat files from a former share as untrusted.

## Network

The default is an empty allowlist: nothing is reachable until a rule allows it.

- Rules match destination addresses, not which machine is behind them. A public
  address that NATs back to the host stays reachable unless it is one of the
  host's own interface addresses.
- The host's interface addresses are collected once, when the VM starts.
- An allowed service is trusted with everything the guest sends it. Terra
  filters destinations, not protocols.
- NAT64 is checked only for the well-known prefix `64:ff9b::/96`. A
  site-specific prefix needs filtering at the translator.
- Learned DNS grants expire for new connections after 60 seconds unless
  renewed. Open TCP connections continue; UDP rechecks on every send and
  receive.

The VM process has no host network access. Every connection goes through a
separate broker process, which checks each request against the recipe even if
the VM process is compromised. Only the broker's own DNS lookups create learned
addresses. Upload buffering is bounded by one stream window per connection.

The broker itself is trusted code. If it is compromised, it can reach whatever
its OS sandbox allows. Services on host loopback or the LAN may have their own
weaknesses; use a host firewall for an extra limit.

## Files

A mount is opened on the host as a directory handle. Guest paths and symlinks
cannot reach outside it. Grant only the tree the workload needs, never device
directories or your whole home directory.

`env_file` reads the host path you give it. `terra sync` checks guest paths,
link targets and destination folders for symlinks before touching them. These
checks assume nothing else changes the destination at the same time, including
the guest through a writable share. Metadata-only copies skip files with
several hard links, so they cannot change another path's permissions or
timestamps. `--delete` removes extra files only inside the destination tree.

With `hw.rootfs_readonly: true`, every boot after setup opens `rootfs.img`
read-only on the host and flags the disk read-only, so guest root cannot change
the root image; the VM worker's sandbox is also granted it read-only. An
overlay volume does not change that: the image stays read-only, and the guest's
root writes go to a `lifetime: boot` volume that is replaced before every boot
and never mounted at a guest path. The flag protects only the image: writable
mounts and `lifetime: box` volumes still keep whatever the guest writes.

## Layers on the host

- **Wasm components.** Each device runs in its own Wasmtime store with its own
  memory and only the host functions it is given. Components get no host
  environment, arguments or standard streams. [Component
  authority](component-authority.md) lists each one's imports.
- **Native checks.** Native code owns the VM, guest RAM and host I/O. It checks
  every guest-memory, disk and memory-reclaim request before acting. Disks have
  a fixed size the guest cannot grow.
- **Boot.** A short-lived component plans the kernel layout. Native code checks
  every write it plans, then destroys it before the VM starts.
- **Devices.** Native code validates MMIO routing and replies, and accepts only
  granted interrupt lines. The network device validates every packet and frame
  before passing bounded requests to the broker.
- **OS sandbox.** The VM and the broker always run as separate sandboxed
  processes; see [host process sandboxing](sandboxing.md). Release builds add a
  per-role syscall allowlist ([host sandbox policy](sandbox-policy.md)). A glibc
  development build has no allowlist, only the broader role filters.

A device can read and corrupt its own VM's RAM. Component isolation protects
the host and other boxes, not a guest from its own devices. A filesystem
component that is compromised still reaches only the directories it was
granted.

## Limits

Terra bounds the work a hostile guest can cause, but it is not a resource
quota.

- Network policies are checked by the same code in the CLI and the broker, with
  fixed size limits. Errors deny access.
- Device requests have deadlines, and device code can be interrupted. A
  deadline does not interrupt host I/O already running or undo a write.
- Each component has its own memory limit: 16 MiB by default, 216 MiB for the
  network device so its 1024-flow table fits. A configured limit must be at
  least 16 MiB. Resource tables and network flows have fixed caps.
- Guest diagnostics are size-limited and written through an 8 MiB per-file
  cap.
- None of these cap guest RAM, host allocations, CPU time, disk use in writable
  shares, or bandwidth. Use OS limits or a dedicated host when you need hard
  isolation.

Terra keeps its state, recipes, images, logs and control sockets under
`~/.terra`, readable only by you where the platform supports it. `terra setup`
refuses to run as host root unless `TERRA_ALLOW_ROOT=1` is set, because root
makes any boundary failure worse.

## Not protected

- **Files the guest writes.** A writable mount is shared storage. Treat
  anything the guest wrote as untrusted before you open, run or parse it on the
  host.
- **Host changes during use.** Changing a mounted tree on the host while the
  box uses it is out of scope.
- **Guest-internal users.** Guest users, guest root, `sudo` and hooks only
  separate things inside the guest. They never give host root.
- **Terminal output.** Attached output comes from the guest and can contain
  terminal control sequences.
- **Bugs below Terra.** Component isolation runs inside one host process. It
  does not survive a bug in Wasmtime, WASI, the native code, the hypervisor or
  the host kernel.
- **Denial of service and side channels.** Terra offers no hard defense
  against these, or against a compromised host OS or build.

For recipe syntax and defaults, see the [recipe reference](recipe.md). To report
a vulnerability, follow the [security policy](../SECURITY.md).
