# Recipe reference

A recipe is the YAML policy for one box: its resources, host access, network,
and workload. `terra setup` pins a copy in the box. Edit the source recipe and
run setup again to apply a change. A project's `terra.yaml` maps box names to
recipes; see [the manifest reference](manifest.md).

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

Increasing a root filesystem or volume limit takes effect on the next boot;
existing images do not shrink. Renaming a volume leaves its prior image behind
and creates an empty one under the new name. `terra <box> setup --rebuild`
removes images for volumes no longer named by the recipe; `storage prune` removes
those orphaned volume images without rebuilding the root filesystem. A box has
at most 32 combined host-directory mounts and volumes on x86_64, or 11 on AArch64.

`volumes` are persistent private guest disks. Each needs a unique plain `name`,
an absolute `guest` path, and a positive `size_mib`; writes past the size fail.
They survive restarts and are removed by `terra rm`.

## Mounts and environment

Each `mounts` item has a host path, an absolute guest path, and optional
`readonly: true`. Host and `env_file` paths resolve relative to the project
directory; `~` expands only for the current user's home. Mount hosts must exist
when the box starts. A mount grants the guest access to that host directory.

Mounts use a scoped WASI directory capability. Guest path traversal and
symlinks cannot open a host path outside that grant. Read-only mounts reject
writes and metadata changes. They support ordinary file I/O, relative symlinks,
and guest execution/mmap. Names must be UTF-8; guest modes and ownership are
synthetic, not host POSIX metadata. Terra has no host-to-guest
file-notification bridge: applications must rescan or poll for host and
other-box edits. Guest-originated inotify remains available. Host edits do not
automatically invalidate guest mapped pages. Use private volumes when an application needs full Linux
filesystem behavior; host chmod/chown, xattrs, and cross-box locks are not
available through a mount.

`env` supplies literal variables to hooks and guest processes. `env_file` is a
dotenv file whose `KEY=VALUE` entries override `env`; blank lines and `#`
comments are allowed. `terra <box> show` redacts environment values unless
`--with-env-values` is specified.

## Network

The default `mode: allowlist` permits no egress until an `allow` entry grants a
hostname, IP address, or CIDR, optionally limited with `:PORT`. A hostname rule
is exact; `*.example.com` matches subdomains, not `example.com` itself.

`mode: unrestricted-public` permits public destinations. The host, LAN,
private ranges, link-local addresses, and cloud-metadata addresses still need
an explicit rule. `HOST_LOOPBACK` names the host running Terra. A `hosts`
record only provides local DNS; add a matching `allow` rule before connecting.
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
