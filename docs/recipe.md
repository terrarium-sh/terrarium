# Recipe reference

A recipe is the YAML policy for one box: its resources, host access, network
and workload. `terra setup` pins a copy in the box; edit the source recipe and
run setup again to apply a change. A project's `terra.yaml` maps box names to
recipes; see [the manifest reference](manifest.md).

Keep recipes and manifests out of writable shares, because the guest could edit
them. If you must share them, review them before every setup, even after
removing the share. See [where recipes live](security.md#where-recipes-live).

An empty recipe gives 2 vCPUs, 1024 MiB RAM, a 512 MiB root filesystem, an
interactive shell, no mounts and no network. Every field:

```yaml
hw:
  cpus: 2
  mem_mib: 1024
  rootfs_mib: 4096
components:
  memory_mib: 16
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
  enabled: true
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

- `hw.cpus`, `hw.mem_mib` and `hw.rootfs_mib` set the vCPUs, guest RAM and root
  filesystem size. The root filesystem is sparse but never grows past
  `rootfs_mib`.
- `components.memory_mib` caps the memory of each of Terra's device
  components: 16 MiB by default and at minimum. Most recipes leave it out.

`volumes` are private guest disks that survive restarts and are deleted by
`terra rm`. Each needs:

- a `name` of up to 247 ASCII letters, digits, `.`, `-` or `_`, unique ignoring
  case. It cannot end in a dot or be a Windows device name such as `CON`.
- an absolute `guest` path.
- a positive `size_mib`. Writes past it fail.

A box has at most 32 mounts and volumes combined on x86_64, or 11 on AArch64.

Growing `rootfs_mib` or a volume takes effect on the next boot; images never
shrink. Renaming a volume creates a new empty one and leaves the old image
behind. `terra <box> storage prune` removes images no longer named by the
recipe; `setup --rebuild` does too.

## Mounts

Each `mounts` item has a `host` path, an absolute `guest` path and optional
`readonly: true`. Host paths are relative to the project directory, and `~`
means your own home. The host directory must exist when the box starts.

A mount gives the guest that directory and nothing outside it: guest paths and
symlinks cannot escape it. Read-only mounts reject writes and metadata changes.

What works through a mount:

- Ordinary file I/O, executing files and `mmap`.
- Relative symlinks. Windows hosts store them WSL-style, and Windows itself
  does not follow them.
- Permission bits on Linux and macOS hosts. On Windows, only the write bits
  work: they map to the file's read-only attribute.

What does not: host `chmod`/`chown`, xattrs, locks shared between boxes, and
non-UTF-8 names. Guest file ownership is synthetic. Use a volume when an
application needs full Linux filesystem behavior.

**Shutdown.** Guest writes reach the host file as they happen, so stopping a box
does not lose them. Terra also gives each mount one second to sync open files
to disk; if that fails or times out, Terra logs an I/O error and the host OS
writes the data out as usual.

**File events.** Host file changes reach guest `inotify` on Linux, macOS and
Windows, including read-only mounts and edits from other boxes. Delivery is
best effort: events can merge, repeat, reorder or drop, and rename cookies are
not kept. Each box watches at most 1,024 directories with 4,096 pending events;
past that, Terra logs a warning. Terra never polls or replays missed changes.
Volumes and `terra sync` copies get no events.

## Environment

`env` sets literal variables for hooks and guest processes. `env_file` is a
dotenv file, relative to the project directory; its `KEY=VALUE` lines override
`env`, and blank lines and `#` comments are allowed. `terra <box> show` hides
values unless you pass `--with-env-values`.

## Network

`network.enabled` defaults to `true`. `network: {enabled: false}` keeps only
guest-local networking: loopback and terra sessions work, external connections
fail and no broker runs. Such a recipe must use allowlist mode with empty
`allow`, `hosts` and `ports`. For how rules are enforced, see
[network](security.md#network).

- **`mode: allowlist`** (default) allows nothing until an `allow` entry names a
  hostname, IP or CIDR, optionally with `:PORT`. Hostnames match exactly;
  `*.example.com` matches subdomains but not `example.com`.
- **`mode: unrestricted-public`** allows public addresses, including public
  addresses on your LAN. The host's own interface IPs, private and link-local
  ranges, and cloud-metadata addresses still need an explicit rule.
- **`hosts`** adds local DNS records. `HOST_LOOPBACK` names the Terra host. A
  record alone allows nothing; add a matching `allow` rule.
- **`ports`** publishes a guest listener on host loopback. `"8080"` maps the
  same port, `"3000:80"` maps host 3000 to guest 80, and `/udp` selects UDP, as
  in `"5353:53/udp"`. TCP and UDP can share a host port. The guest service must
  listen on all interfaces, such as `0.0.0.0`: a listener on `127.0.0.1` alone
  is unreachable.

Limits:

- A box has at most 1024 network flows at once, outbound and published
  together.
- A UDP datagram carries at most 4 KiB.
- DNS answers A and AAAA queries only; MX, TXT, SRV and other types come back
  empty. The host follows CNAMEs, so the guest gets addresses under the name it
  asked for, and only that name needs an `allow` rule.
- An address learned from a lookup allows new connections for 60 seconds unless
  a new lookup renews it; open connections are unaffected.
- `ping` to external hosts does not work: there is no ICMP forwarding.

## Processes

- `hooks.on_create` runs once as guest root during setup, before mounts exist.
  It uses the recipe's network rules, and setup prints its output.
- `hooks.on_start` runs as guest root before every workload start.
- `hooks.pre_stop` runs during an orderly stop.
- `on_start` and `pre_stop` output go to the box's session.
- `daemons` are background shell commands. A nonzero exit restarts the daemon
  after one second; exit zero ends it.

The workload and daemons run as `terri` (UID 1000). `workload.entrypoint`
defaults to `/bin/sh`, `args` are passed as written, and `workdir` must be
absolute. `sudo` lets the workload user run the named commands as guest root,
with any arguments. `terra <box> --root` runs that boot's workload and daemons
as root; `terra <box> exec --root -- CMD` runs only that command as root.

## Applying changes

Stop the box and run `terra <box> setup` after editing a recipe. `--dry-run`
checks it without changing anything. `--rebuild` discards the root filesystem,
reruns `on_create` and removes volume images the recipe no longer names; without
it, an edited `on_create` does not run. Read
[usage](usage.md) and [security](security.md) before granting host access.
