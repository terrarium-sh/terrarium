# Recipe reference

A recipe is the YAML policy for one box: its resources, host access, network,
and workload. `terra setup` pins a copy into the box; every later boot uses that
copy. Edit the recipe, then run `terra setup` again to apply a change. A
project's `terra.yaml` names boxes and points to their recipes; see
[manifest.md](manifest.md). For the CLI and box lifecycle, see
[usage.md](usage.md).

Every key is optional. An empty recipe gives a box 2 vCPUs, 1 GiB RAM, a 512 MiB
writable root filesystem, an interactive shell, no host files, and no network.

```yaml
# Guest resources. Defaults: 2 vCPUs, 1024 MiB RAM, 512 MiB rootfs.
hw:
  cpus: 2                 # virtual CPUs
  mem_mib: 1024           # guest RAM
  rootfs_mib: 4096        # bounded, private writable root filesystem; can grow, not shrink

# Host directories visible inside the guest. Omit for no host filesystem access.
# libkrun does not confine a mount to this directory; see security.md.
mounts:
  - host: .               # relative paths resolve from the project directory
    guest: /work          # absolute path in the guest
    readonly: false       # true prevents guest writes

# Private, persistent guest disks. They survive restart and are removed by `terra rm`.
volumes:
  - name: data            # stable disk identity; changing it leaves this disk and creates a new empty one
    guest: /data          # absolute guest mount point
    size_mib: 1024        # hard size cap; further writes fail with ENOSPC

# Variables supplied to hooks and the workload.
env:
  MODEL: gpt-6
env_file: .env            # project-relative dotenv file merged over env; values are literal

# Egress, local DNS records, and host-loopback port publishing.
network:
  mode: unrestricted-public  # public egress; allowlist is the no-network default
  allow:                    # hostname, IP, or CIDR, optionally with :PORT
    - db.local:5432         # opens this locally defined service
  hosts:
    - name: db.local
      addr: HOST_LOOPBACK    # the machine running terra; a record alone is not a grant
  ports:
    - "3000:80"             # host 127.0.0.1:3000 -> guest :80

# Commands run as guest root.
hooks:
  on_create:                # once during setup, baked into the rootfs with no host mounts
    - apk add --no-cache git
  on_start:                 # before every workload start
    - echo ready
  pre_stop:                 # on orderly shutdown
    - echo cleaning up

# Background shell commands beside the workload; non-zero exits restart after one second.
daemons:
  - ascend --serve

# Commands the workload user may run as guest root, with any arguments.
sudo:
  - apk

# The program to run as terri (UID 1000) unless terra is invoked with --root.
workload:
  entrypoint: /bin/sh      # defaults to an interactive shell
  args: []                 # literal argv after entrypoint
  workdir: /work           # absolute guest directory; created if needed
```

## Network

`mode: allowlist` is the default: the box cannot make an external connection
until an `allow` rule permits it. It can still ask Terra's built-in DNS server;
that server answers `hosts` records and forwards only names named by `allow`.
Every other name returns `NXDOMAIN`. `mode: unrestricted-public` permits the
public internet, while the host, LAN, and private ranges remain blocked unless
an `allow` rule grants them.

A hostname rule is exact; `*.example.com` grants subdomains but not
`example.com`. `hosts` supplies a DNS record; add a matching `allow` rule to
reach it. `HOST_LOOPBACK` names the machine running terra. `ports` publishes
guest listeners on host loopback only: `"8080"` maps 8080 to 8080, and
`"3000:80"` maps host 3000 to guest 80.

The network policy is the box's egress filtering. Read the
[security model](security.md) for DNS, CIDR, and isolation limits.

## What runs when

`on_create` runs once, as guest root, while `terra setup` builds the box. Its
changes stay in the box's filesystem, and it runs before any host folders are
shared. Put slower package installation here.

`on_start` runs as guest root before every start. `pre_stop` runs during an
orderly stop, after the workload is signalled and before the VM exits. Hooks are
shell commands.

The workload and daemons run as `terri` (UID 1000) by default. `sudo`
allows specific commands as guest root; `terra --root` runs the main workload
as root. These rules protect the box's own files. The VM is what protects the
host.

## Changing or removing a box

`terra setup` is the explicit way to pin a recipe. An interactive
`terra <box>` can offer the same setup; accepting it pins the recipe too.
Re-run `terra setup` after a recipe change; growing a root filesystem or volume
takes effect on the next boot. Use `terra setup --rebuild` to discard old box
storage while rebuilding, or `terra rm` to remove the box. See
[usage.md](usage.md) for command details and storage cleanup.
