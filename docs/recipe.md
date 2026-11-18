# Recipe reference

A recipe is the YAML policy for one box: its resources, host access, network
and workload. `terra setup` applies a copy to the box; edit the source recipe and
run setup again to apply a change. A project's `terra.yaml` maps box names to
recipes; see [the manifest reference](manifest.md).

Keep recipes and manifests out of writable shares, because the guest could edit
them. If you must share them, review them before every setup, even after
removing the share. See [where recipes live](security.md#where-recipes-live).

An empty recipe gives 2 vCPUs, 1024 MiB RAM, a 512 MiB root filesystem, an
interactive shell and no setup or workload mounts. Networking is enabled with
an empty allowlist, so external connections are blocked. Every field:

```yaml
hw:
  cpus: 2
  mem_mib: 1024
  rootfs_mib: 4096
  rootfs_readonly: false
components:
  memory_mib: 16
volumes:
  - name: data
    guest: /data
    size_mib: 1024
    lifetime: box
  # rootfs_overlay: true needs hw.rootfs_readonly: true
  # - name: changes
  #   rootfs_overlay: true
  #   size_mib: 1024
  #   lifetime: boot
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
setup:
  run: [apk add --no-cache git]
  workdir: /setup
  mounts:
    - host: ./setup
      guest: /setup
      readonly: true
workload:
  workdir: /work
  mounts:
    - host: .
      guest: /work
      readonly: false
  on_start: [echo ready]
  pre_stop: [echo stopping]
  daemons: []
  sudo: [apk]
  run: exec npm run dev
```

## Resources and storage

- `hw.cpus`, `hw.mem_mib` and `hw.rootfs_mib` set the vCPUs, guest RAM and root
  filesystem size. The root filesystem is sparse but never grows past
  `rootfs_mib`.
- `hw.rootfs_readonly: true` keeps the root image unchanged on every boot after
  setup. See [read-only root](#read-only-root).
- `components.memory_mib` caps the memory of each of Terra's device
  components: 16 MiB by default and at minimum. Most recipes leave it out.

`volumes` are private guest disks, deleted by `terra rm`. Each needs:

- a `name` of up to 247 ASCII letters, digits, `.`, `-` or `_`, unique ignoring
  case. It cannot end in a dot or be a Windows device name such as `CON`.
- an absolute `guest` path other than `/`, or `rootfs_overlay: true` to take a
  read-only root's writes instead (see [overlay volume](#overlay-volume)).
- a positive `size_mib`. Writes past it fail.

`lifetime` says how long a volume's data lasts. The default, `box`, keeps it
across restarts. `boot` gives the volume an empty filesystem of `size_mib` on
every boot, even after a crash, so nothing written to it survives a restart.

Each phase has at most 32 mounts and volumes combined on x86_64, or 11 on
AArch64.

Changing `rootfs_mib` rebuilds the root filesystem at the new size at the next
`terra <box> setup`, so it can shrink as well as grow. Any change to
`volumes`, a size included, also rebuilds the root and reruns setup, because
setup can write into volumes. Growing a
`lifetime: box` volume takes effect at that setup; its image never shrinks. A
`lifetime: boot` volume
is recreated at its configured size on every boot, so it can shrink as well as
grow. Renaming a volume creates a new empty one and leaves the old image
behind.
`terra <box> storage prune` removes images no longer named by the recipe;
`setup --rebuild` does too.
`terra <box> storage export` writes the applied recipe, including inline `env:`
values, and the images; `storage import` asks before applying that recipe
(`--trust-recipe` skips the question), and the box boots straight after it.
The imported recipe's `workload.mounts` and `env_file` resolve against the
importing project, so those paths must exist there. The first build after
import checks the local `setup.mounts` targets and asks for approval.

### Read-only root

With `hw.rootfs_readonly: true`, the root image never changes after setup. Setup
prepares and writes it as usual; every other boot attaches it read-only on the
host, so not even guest root can change it. `lifetime: box` volumes and
writable workload mounts still persist.

Without an [overlay volume](#overlay-volume), every later write to the root
fails with `EROFS`: from the workload, daemons, `on_start`, `pre_stop`, `workload.sudo`,
`exec --root` and `terra sync`, so a runtime `apk add` fails too. The
workload's home, `/home/terri`, is read-only as well. To get a writable home,
add a `lifetime: boot` volume at `/home/terri`; it starts empty on every boot.
`/tmp`, `/var/tmp` and `/run` are tmpfs in guest RAM.

#### Overlay volume

A volume with `rootfs_overlay: true` in place of `guest` makes a read-only root
writable for one boot:

```yaml
hw: {rootfs_readonly: true}
volumes:
  - {name: changes, rootfs_overlay: true, size_mib: 4096, lifetime: boot}
```

The guest's root is an overlay: the root image below, unchanged, and the volume
on top, which takes every write to the root. The volume is never mounted at a
guest path. It needs `hw.rootfs_readonly: true` and `lifetime: boot`, and a box
has at most one. Root writes past its `size_mib` fail with `ENOSPC`.

Everything written to the root lasts until the box stops: installed packages,
edits under `/etc`, the home directory, `/tmp`, `/var/tmp` and `/var/log`. The
next boot, even after a crash, starts again from the image setup left. To keep
something, install it in `setup.run` and run setup, or write it to a mount or a
`lifetime: box` volume, such as one at `/var/log`.

Programs can tell the root is an overlay:

- Renaming a directory that came from the image fails with `EXDEV`; `mv` falls
  back to copying.
- A file's inode number changes when it is first modified, and hard links to a
  file from the image split.
- Container engines cannot keep their storage on the root; see
  [containers](#containers).

## Mounts

A recipe has two mount lists, one per phase. `setup.mounts` exist only while
setup prepares the root image. `workload.mounts` exist only during normal runs -
`on_start`, the workload, daemons, `pre_stop` and `exec`. Both lists default to
read-write; set `readonly: true` to protect host inputs from changes. There is
no inheritance: a host directory needed in both phases is listed in both.

Both lists take a `host` path and an absolute `guest` path other than `/`. Host
paths are relative to the project directory, and `~` means your own home.
Terra checks the `setup.mounts` host directories when setup creates or
rebuilds the root image. A dry run checks them if it would build the root.
`terra show` displays the setup mount declarations without checking their
host targets. Normal boots, imports and setup runs that keep the root can
proceed even when setup mount sources are missing.

The same guest path may appear in both lists because those shares attach in
separate phases.
Within each phase, mount and volume guest paths must be separate: neither
duplicate nor nested targets are allowed. Mount at separate paths and use a
symlink in a guest-owned directory where a tool needs a different layout.

A mount gives the guest that directory and nothing outside it: guest paths and
symlinks cannot escape it. Read-only mounts reject writes and metadata changes.
File names containing `\` or `:` are refused on every host, because Windows would
store them as subfolders and alternate data streams.

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

`env` sets literal variables for both phases and guest processes. `env_file` is a
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
- In allowlist mode, or with `hosts` records, all guest DNS goes to Terra's
  resolver, so an `allow` rule for port 53 is refused.
- An address learned from a lookup allows new connections for 60 seconds unless
  a new lookup renews it; open connections are unaffected.
- `ping` to external hosts does not work: there is no ICMP forwarding.

### Proxies

Rules match addresses, not TLS names or request contents. To filter by
hostname, or to keep API keys out of the box, allow only a proxy and point the
guest at it:

```yaml
network:
  allow: [proxy.local:3128]
  hosts:
    - { name: proxy.local, addr: HOST_LOOPBACK }
env:
  HTTPS_PROXY: http://proxy.local:3128
  HTTP_PROXY: http://proxy.local:3128
  https_proxy: http://proxy.local:3128
  http_proxy: http://proxy.local:3128
```

The proxy decides which names the guest reaches, and it can add credentials to
requests so the real key never enters the box. Setup commands use the proxy too.
Adding headers to HTTPS requests needs a proxy that terminates TLS, with its CA
installed in the guest. Tools that ignore the proxy variables cannot connect.

## Processes

- Setup prepares the root image in an isolated VM with `setup.mounts` and the
  recipe's volumes, and sizes the root image and `lifetime: box` volumes. A
  start never prepares the root image. Running setup again on an unchanged
  recipe boots no VM.
- `setup.run` runs as guest root whenever setup builds a new root image (the
  first setup, a recipe change that rebuilds and `--rebuild`). The workload
  user `terri` already exists. Setup's writes under a volume's `guest` path
  land in the volume, so a `lifetime: boot` volume loses them at the next boot.
  Setup uses the recipe's network rules and prints its output. A failed setup
  leaves no successful stamp, so the next setup builds the root again.
- Both phases start in their own `workdir`: `setup.workdir` defaults to `/`,
  and `workload.workdir` defaults to `/home/terri`. Setup enters its workdir
  after attaching setup mounts and volumes; a missing directory is created when
  its filesystem is writable, and an unusable path fails setup. Setup creates
  runtime mount points as root and missing `workload.workdir` directories as
  `terri`. Existing directories keep their ownership, including a directory
  created for `setup.workdir`; use `setup.run` to change its ownership if the
  workload needs write access. Paths prepared in the root image support a
  read-only runtime root.
  Mounts can hide those paths: the workdir must exist on the filesystem visible
  at runtime, or that filesystem must be writable so the directory can be created.
- Every workload boot writes `/terra/README.md` for software inside the box.
  It describes the user, root filesystem, workload, mounts and egress policy.
  Its configuration lists environment variable names and omits their values,
  the host `env_file` path and the setup section.
- `workload.on_start` runs as guest root before every workload start.
- `workload.pre_stop` runs during an orderly stop.
- `on_start` and `pre_stop` output go to the box's session.
- Lifecycle commands write to the box's terminal, so tools that detect one show
  colors and progress bars.
- `on_start`, `pre_stop`, daemons and the workload run in `workload.workdir`.
- `workload.daemons` are background shell commands. A nonzero exit restarts the
  daemon after one second; exit zero ends it.

The workload and daemons run as `terri` (UID 1000). `workload.run` is a shell
command run with `/bin/sh -c`, like a daemon; unset, the workload is an interactive
`/bin/sh`. Write `exec PROGRAM ...` to make the program the workload process, so
stop signals reach it directly; `terra <box> exec -- CMD` runs anything else in
the running box. Both workdirs must be absolute. `workload.sudo` lets the workload user run the named
commands as guest root, with any arguments. `terra <box> --root` runs that boot's workload and daemons
as root; `terra <box> exec --root -- CMD` runs only that command as root.

## Containers

Rootless podman runs as `terri`. The image already ships `terri`'s
subordinate IDs and a `containers.conf` that suits the guest, so on a writable
root `setup: {run: [apk add podman]}` is all it takes. Images then live on
the root, so size `hw.rootfs_mib` for them.

Podman's storage must be on a writable filesystem that is not an overlay. Its
default, `~/.local/share/containers/storage`, is on the root, so a read-only
root needs a volume for it, with or without an overlay volume: a plain
read-only root refuses the write, and on an overlay root podman stops with
`'overlay' is not supported over overlayfs`. Point `graphroot` at the volume in
a `storage.conf` written by setup; these `allow` rules cover Alpine
packages and Docker Hub:

```yaml
hw: {rootfs_readonly: true}
network:
  allow:
    - dl-cdn.alpinelinux.org:443
    - registry-1.docker.io:443
    - auth.docker.io:443
    - production.cloudflare.docker.com:443
    - production.cloudfront.docker.com:443
volumes:
  - {name: changes, rootfs_overlay: true, size_mib: 4096, lifetime: boot}
  - {name: containers, guest: /var/lib/terri-containers, size_mib: 8192}
setup:
  run:
    - apk add podman
    - |
      cat > /home/terri/.config/containers/storage.conf <<'EOF'
      [storage]
      driver = "overlay"
      graphroot = "/var/lib/terri-containers/storage"
      EOF
```

A `lifetime: box` volume keeps pulled images across restarts; `lifetime: boot`
starts every boot clean. Keep the volume outside `/home/terri`: setup creates a
volume's missing parent directories as root, so `terri` could not write in
them.

## WireGuard

Use `wireguard-go` in the guest. Install `wireguard-go`, `wireguard-tools`
and `iproute2` in `setup.run`, then create and configure the TUN interface as
guest root (`terra <box> exec --root -- ...`). Start the interface with
`wireguard-go wg0` and configure it with `wg` and `ip`.

The encrypted UDP socket goes through Terra's network broker directly. Allow
the remote peer's address and port in `network.allow`. No separate UDP relay
is needed. A 1280-byte MTU, the IPv6 minimum, fits comfortably inside Terra's
4 KiB UDP datagram limit and leaves room for WireGuard's outer headers. Use a
persistent keepalive for idle connections.

Keep the peer's outer UDP traffic outside the tunnel routes. For a full tunnel,
start `wireguard-go` in the initial guest network namespace, then move its TUN
interface into a separate workload network namespace and install the default
routes there. The process's UDP sockets remain in the initial namespace.
An ordinary `wg-quick` default-route setup is not covered by this configuration.

The broker checks the VPN peer's address and port, not destinations inside the
encrypted tunnel. Only allow a VPN peer you trust to enforce the intended
access restrictions. See [network security](security.md#network).

## Applying changes

Stop the box after editing its recipe. If the box has a [manifest alias](manifest.md),
run `terra <box> setup`. Otherwise, pass the original recipe path again with
`terra <recipe-path> setup`: a box name without an alias reuses the applied copy.
An explicit path always reads that file and names the box by its file stem.
`--dry-run` checks the recipe without changing anything. A change that affects
the root filesystem rebuilds it from scratch and reruns setup. Terra keeps
`lifetime: box` volumes.
A change only to fields that do not shape the root filesystem is applied
without a rebuild: `workload.run`, `workload.on_start`,
`workload.pre_stop`, `workload.daemons`, `workload.sudo`,
`network.ports`, `hw.rootfs_readonly`, `components`, and a workload mount's
`host` and `readonly`. A workload mount's `guest` path and
`workload.workdir` are baked into the root as directories, so changing either
rebuilds. `setup.run`, `setup.workdir` and `setup.mounts` all shape the root and
rebuild it. Setup runs under the recipe's egress rules, so editing
`network.enabled`, `mode`, `allow` or `hosts` rebuilds. Comments, layout,
quoting, key order and a field written with the value it has when left out
(`cpus: 2`) are not changes. With an unchanged recipe, run `setup --rebuild`
to pick up changes to values in `env_file` that setup uses, files a setup
mount consumes, or a setup mount source symlink. A build that uses a different
target for a previously approved setup mount asks for approval again.
`--rebuild` also removes volume images the recipe no longer names. Read
[usage](usage.md) and [security](security.md) before granting host access.
