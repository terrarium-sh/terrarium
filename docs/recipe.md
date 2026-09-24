# Recipe reference

A recipe is the YAML policy for one box: its resources, host access, network,
and workload. `terra setup` pins a copy in the box. Edit the source recipe and
run setup again to apply a change. A project's `terra.yaml` maps box names to
recipes; see [the manifest reference](manifest.md).

Prefer storing recipes and manifests outside guest-writable shares. If your
workflow requires sharing them writable, review them before setup, even after
removing the share: guest-written files remain on the host. See
[recipe storage and trust](security.md#recipe-storage).

An empty recipe creates a box with 2 vCPUs, 1024 MiB RAM, a 512 MiB writable
root filesystem, an interactive shell, no host mounts, and no network.

```yaml
hw:
  cpus: 2
  mem_mib: 1024
  rootfs_mib: 4096
components:
  memory_mib: 16
  total_memory_mib: 128
mounts:
  - host: .
    guest: /work
    readonly: false
volumes:
  - name: data
    guest: /data
    size_mib: 1024
env:
  MODEL: example
env_file: .env  # create this file, or omit env_file
network:
  mode: allowlist
  allow: [dl-cdn.alpinelinux.org:443, db.local:5432]
  hosts:
    - { name: db.local, addr: HOST_LOOPBACK }
  ports: ["3000:80"]
hooks:
  on_create: [apk add --no-cache git]
  on_start: [echo ready]
  pre_stop: [echo stopping]
daemons: []
sudo: [apk]
workload:
  entrypoint: /bin/sh
  args: []
  workdir: /work
```

## Resources and storage

`hw.cpus`, `hw.mem_mib`, and `hw.rootfs_mib` set virtual CPUs, guest RAM, and
the private writable root filesystem capacity. The root filesystem is sparse,
but it cannot exceed `rootfs_mib`. `components.memory_mib` limits each Wasm
component's linear memory and `components.total_memory_mib` limits their total.
Both must be positive, and the total must be at least the per-component value.
The defaults are 16 MiB per component and 128 MiB in total. These limits are
separate from guest RAM and do not bound all native host-process memory.

On x86_64, RAM starts at zero and skips the reserved device-address region
from 3.25 GiB to 4 GiB, continuing above 4 GiB when needed. Virtio devices
and interrupt controllers retain fixed addresses in that gap. `hw.mem_mib`
counts mapped RAM, excluding the gap; Linux reserves some RAM for boot data.
RAM capacity is constrained by host resources and the platform's address space.

Increasing a root filesystem or volume limit takes effect on the next boot;
existing images do not shrink. Renaming a volume leaves its prior image behind
and creates an empty one under the new name. `terra <box> setup --rebuild`
removes images for volumes no longer named by the recipe; `storage prune` removes
those orphaned volume images without rebuilding the root filesystem. A box has
at most 32 combined host-directory mounts and volumes on x86_64, or 11 on AArch64.

`volumes` are persistent private guest disks. Each needs a unique portable `name`,
an absolute `guest` path, and a positive `size_mib`; writes past the size fail.
Names use 1-247 ASCII letters, digits, `.`, `-`, or `_`, without a trailing dot or
a Windows device name such as `CON`. Names must be distinct ignoring ASCII case
on every platform; Unicode volume IDs are unsupported. The length limit leaves
room for the image filename prefix and suffix.
They survive restarts and are removed by `terra rm`.

## Mounts and environment

Each `mounts` item has a host path, an absolute guest path, and optional
`readonly: true`. Host and `env_file` paths resolve relative to the project
directory; `~` expands only for the current user's home. Mount hosts must exist
when the box starts. A mount grants the guest access to that host directory.

Mounts use a scoped WASI directory capability. Guest path traversal and
symlinks cannot open a host path outside that grant. Read-only mounts reject
writes and metadata changes. They support ordinary file I/O, relative symlinks,
and guest execution/mmap. Names must be UTF-8; guest ownership is synthetic.
Linux and macOS hosts expose Unix permission bits. On Windows, regular files
report mode `0755`, or `0555` when the read-only attribute is set. Setting any
write bit clears that attribute; clearing all write bits sets it. Owner/group
distinctions and executable bits remain synthetic, and Windows ACLs are unchanged.
Windows directories report `0755`; other directory modes are unsupported.
Lookup, stat, and chmod do not require content-read permission. Write-only files
can be opened for writing; reopening checks inode identity before truncation.
On macOS, inaccessible objects use a parent-directory-relative metadata reference.
If the host renames, removes, or replaces such an object, its cached guest reference
returns not-found; look it up again at its current path. Files already opened for
content access keep their normal descriptor semantics.

Each shared mount allows 32 active filesystem requests and 256 outstanding
requests including queued work. Reads, writes, flushes, and metadata operations
use the same queue; these are individual requests, not whole copy jobs. Reads,
writes, and flushes on the same file run in order. Event resolution has one
reserved operation, and cancellation bypasses the scheduler with reserved
virtio-fs ring capacity. If all 32 operations stall, further queued filesystem
work waits for capacity. Each mount has its own runtime with at most 33 blocking
threads for filesystem operations and descriptor cleanup. Saturating that pool
does not consume the pools used by other mounts or guest disks. Shared underlying
host storage failures can still affect every user of that storage.

On shutdown, each shared mount has one second to flush its open writable files.
A failed or timed-out flush reports an I/O error and allows shutdown to continue;
durability is not guaranteed after that error. An already-running host filesystem
operation may still complete after shutdown.
Descriptor cleanup runs off the worker and retains its resource reservation
until it completes. Process teardown waits at most one second for remaining
runtime tasks; this does not force the host OS to complete stalled filesystem I/O.

Terra forwards native host file events to guest `inotify` automatically on Linux,
macOS, and Windows hosts, including read-only mounts and other-box edits.
Events travel through the virtio-fs filesystem worker and the bundled FUSE driver.
Guest writes generate native host notifications through ordinary filesystem I/O.
Delivery is best effort: events can be coalesced, duplicated, reordered, or lost;
rename cookies and exact event counts are not preserved. Watcher failures and
queue overflow produce rate-limited diagnostics without stopping the box.
Watcher registration waits asynchronously for up to one second before the
filesystem component starts. A timeout disables notifications for that mount
and lets startup continue; the watcher stops when its blocked host call returns.
Each box shares a budget of 4,096 pending events and 1,024 watched directories
across its mounts. Directories beyond the watch limit receive no notification
coverage; reaching the limit produces a rate-limited diagnostic.
Terra does not poll, rescan, or replay missed changes. Filesystems without native
notifications cannot provide automatic reload through this bridge. Host edits do
not automatically invalidate guest mapped pages. Private disks and `sync` transfers
receive no additional notification bridge.

Use private volumes when an application needs full Linux filesystem behavior; host chmod/chown, xattrs, and cross-box locks are not
available through a mount.

`env` supplies literal variables to hooks and guest processes. `env_file` is a
dotenv file whose `KEY=VALUE` entries override `env`; blank lines and `#`
comments are allowed. `terra <box> show` redacts environment values unless
`--with-env-values` is specified.

## Network

The default `mode: allowlist` permits no egress until an `allow` entry grants a
hostname, IP address, or CIDR, optionally limited with `:PORT`. A hostname rule
is exact; `*.example.com` matches subdomains, not `example.com` itself.

`mode: unrestricted-public` permits public destinations, including public
addresses on a LAN. Filtering is based on destination addresses, not network
location. IPs collected from host interfaces at VM startup (including public
IPs), private ranges, link-local addresses, and blocked cloud-metadata addresses
still need an explicit rule. `HOST_LOOPBACK` names the host running Terra.
A `hosts` record only provides local DNS; add a matching `allow` rule before
connecting.
`ports` publishes a guest listener on host loopback: `"8080"` maps the same
port and `"3000:80"` maps host 3000 to guest 80.

External ICMP echo forwarding is unavailable, so TCP or UDP rules do not enable
external `ping`. DNS returns A and AAAA records only. Terra uses a 60-second DNS
cache hint: an address learned from a lookup permits new connections for 60
seconds unless another lookup renews it; an existing connection is unaffected.

## Processes

`hooks.on_create` runs once as guest root during setup, before host mounts are
available. `hooks.on_start` runs as guest root before every workload start, and
`pre_stop` runs during an orderly stop. `daemons` are background shell commands:
a nonzero exit restarts after one second; exit zero ends that daemon.

The workload and daemons run as `terri` (UID 1000) by default. `workload.entrypoint`
defaults to `/bin/sh`; `args` are passed literally. `workdir`, when given, must
be absolute. `sudo` grants the workload user named commands as guest root with
any arguments. `terra <box> --root` runs that boot's workload and daemons as
guest root; `terra <box> exec --root -- CMD` affects only that command.

## Applying changes

Run `terra <box> setup` after editing a recipe. `--dry-run` validates setup
without changing state. `--rebuild` discards the guest root filesystem, reruns
`on_create`, and removes volume images no longer named by the recipe. Read
[usage](usage.md) and [security](security.md) before granting host access.
