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
  rootfs_readonly: false
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

A box has at most 32 mounts and volumes combined on x86_64, or 11 on AArch64.

Growing `rootfs_mib` or a `lifetime: box` volume takes effect at the next
`terra <box> setup`; an existing image never shrinks. A `lifetime: boot` volume
is recreated at its configured size on every boot, so it can shrink as well as
grow. Renaming a volume creates a new empty one and leaves the old image
behind.
`terra <box> storage prune` removes images no longer named by the recipe;
`setup --rebuild` does too.
`terra <box> storage export` writes the pinned recipe, including inline `env:`
values, and the images; `storage import` asks before pinning that recipe
(`--trust-recipe` skips the question), and the box boots straight after it.
The imported recipe's mounts and `env_file` resolve against the importing
project, so the paths it names must exist there.

### Read-only root

With `hw.rootfs_readonly: true`, the root image never changes after setup. Setup
prepares it, and `on_create` writes it as usual; every other boot attaches it
read-only on the host, so not even guest root can change it. `lifetime: box`
volumes and writable mounts still persist.

Without an [overlay volume](#overlay-volume), every later write to the root
fails with `EROFS`: from the workload, daemons, `on_start`, `pre_stop`, `sudo`,
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
something, install it in `on_create` and run setup, or write it to a mount or a
`lifetime: box` volume, such as one at `/var/log`.

Programs can tell the root is an overlay:

- Renaming a directory that came from the image fails with `EXDEV`; `mv` falls
  back to copying.
- A file's inode number changes when it is first modified, and hard links to a
  file from the image split.
- Container engines cannot keep their storage on the root; see
  [containers](#containers).

## Mounts

Each `mounts` item has a `host` path, an absolute `guest` path other than `/`
and optional `readonly: true`. Host paths are relative to the project directory, and `~`
means your own home. The host directory must exist when the box starts.

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
- In allowlist mode, or with `hosts` records, all guest DNS goes to Terra's
  resolver, so an `allow` rule for port 53 is refused.
- An address learned from a lookup allows new connections for 60 seconds unless
  a new lookup renews it; open connections are unaffected.
- `ping` to external hosts does not work: there is no ICMP forwarding.

## Processes

- Setup prepares the root image in an isolated VM with the recipe's volumes but
  no shares, with or without `on_create`, and sizes the root image and
  `lifetime: box` volumes. A
  start never prepares the root image. Running setup again on an unchanged
  recipe boots no VM.
- `hooks.on_create` runs as guest root only when setup builds a new root image
  (the first setup and `--rebuild`), with volumes mounted and shares not; the
  workload user `terri` already exists. Its writes under a volume's `guest`
  path land in the volume, so a `lifetime: boot` volume loses them at the next
  boot. It uses the recipe's network rules, and setup prints
  its output. If it fails, the next setup builds the root again from scratch.
- `hooks.on_start` runs as guest root before every workload start.
- `hooks.pre_stop` runs during an orderly stop.
- `on_start` and `pre_stop` output go to the box's session.
- `on_start`, `pre_stop`, daemons and the workload run in `workload.workdir`
  (`/home/terri` when unset); `on_create` runs in `/`, since shares are not
  mounted during setup.
- `daemons` are background shell commands. A nonzero exit restarts the daemon
  after one second; exit zero ends it.

The workload and daemons run as `terri` (UID 1000). `workload.entrypoint`
defaults to `/bin/sh`, `args` are passed as written, and `workdir` must be
absolute. `sudo` lets the workload user run the named commands as guest root,
with any arguments. `terra <box> --root` runs that boot's workload and daemons
as root; `terra <box> exec --root -- CMD` runs only that command as root.

## Containers

Rootless podman runs as `terri`. The image already ships `terri`'s
subordinate IDs and a `containers.conf` that suits the guest, so on a writable
root `on_create: [apk add podman]` is all it takes. Images then live on the
root, so size `hw.rootfs_mib` for them.

Podman's storage must be on a writable filesystem that is not an overlay. Its
default, `~/.local/share/containers/storage`, is on the root, so a read-only
root needs a volume for it, with or without an overlay volume: a plain
read-only root refuses the write, and on an overlay root podman stops with
`'overlay' is not supported over overlayfs`. Point `graphroot` at the volume in
a `storage.conf` written by `on_create`; these `allow` rules cover Alpine
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
hooks:
  on_create:
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

## Applying changes

Stop the box and run `terra <box> setup` after editing a recipe. `--dry-run`
checks it without changing anything. `--rebuild` discards the root filesystem,
reruns `on_create` and removes volume images the recipe no longer names; without
it, an edited `on_create` does not run, and setup says so. Read
[usage](usage.md) and [security](security.md) before granting host access.
