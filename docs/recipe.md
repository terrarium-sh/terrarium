# The recipe

The YAML file that says what a box is: its hardware, its shares, its network,
what runs inside it. One format, two ways to name one: a file by path
(`terra ./ci.yaml setup`), or an entry in the project's `terra.yaml` pointing
at one. Either way, `setup` copies it into the box as its pinned `recipe.yaml`
— the copy every boot uses. See also [usage.md](usage.md) for the CLI side.

Every key is optional — an empty recipe is valid (2 vCPU, 1 GiB, a 512 MiB
rootfs, an interactive shell, **no host filesystem**, and **no network at all**:
the default mode is `allowlist`, and an allowlist with no rules reaches nothing).

```yaml
# a recipe — every key below is optional
hw:
  cpus: 2
  mem_mib: 1024
  rootfs_mib: 4096     # size of the writable rootfs (sparse ext4); default 512, always bounded
                       # raising it later grows the image in place; lowering warns and is ignored
mounts:                # nothing is shared unless it is listed here
  - host: .            # this project directory…
    guest: /work       # …visible to the guest here
  - host: ~/.ssh
    guest: /home/terri/.ssh
    readonly: true
volumes:               # empty fixed-size ext4 disks, persistent per box
  - name: data         # names the image file, so the data survives reordering
    guest: /data
    size_mib: 1024     # writes past the cap fail with ENOSPC; raise it later to grow
env:                   # exported for hooks + the workload
  MODEL: gpt-4o
env_file: .env         # dotenv merged over env: (the file wins; values are
                       # literal — quotes are not stripped, unlike compose)
network:
  mode: allowlist      # unrestricted-public | allowlist (the default; no rules = no egress)
  allow:
    - api.openai.com:443   # HOST-or-IP-or-CIDR[:PORT]; no :PORT = any port
    - "*.githubusercontent.com"   # a name covers everything under it, with or
                                  # without the `*.` (quoted: YAML reads a bare
                                  # leading `*` as an alias)
  hosts:                   # DNS records the gateway answers itself, either mode
    - {name: db.local, addr: HOST_LOOPBACK}  # the machine terra runs on
    - {name: nas.local, addr: 10.0.0.5}  # …or anything the host can reach
                                         # (a record resolves; `allow:` opens)
  ports:                   # publish a guest listener on the host loopback
    - "8080"               # 127.0.0.1:8080 -> guest:8080
    - "3000:80"            # 127.0.0.1:3000 -> guest:80
sudo:                  # commands terri may run as root (via doas / sudo)
  - apk
hooks:
  on_create:               # once, when the box is built (baked into its rootfs)
    - apk add --no-cache git
  on_start:                # every boot, before the workload
    - echo ready
  pre_stop:
    - echo "cleaning up"
workload:
  entrypoint: /bin/sh
  args: []
  workdir: /work           # where it starts; default: the workload user's home
```

- **hw**: CPU/memory defaults, scoped here so hardware isn't repeated per
  profile. `rootfs_mib` sizes the writable rootfs (defaults to 512 MiB; must be
  `> 0` — the rootfs is *always* a bounded, private **sparse** ext4 image, so it
  only consumes what's written and a runaway workload can't exceed it). Raise it
  for heavy `on_create` installs. Live host
  mounts are never capped; use `volumes` for bounded scratch data. Raising
  `rootfs_mib` (or a volume's `size_mib`) on an existing box grows the image in
  place and the guest expands the filesystem on the next boot; lowering it warns
  and keeps the current size, since shrinking would truncate live data
  (`terra rm` then `terra <box>` rebuilds it smaller).
  Terra's own guest pieces don't come from the rootfs image (the PID-1 agent and the `resize2fs`
  that grows it ride the boot volume), so what it needs is only what your recipe
  asks of it: `/bin/sh` for `hooks:`, `ip` for a network, a uid 1000 for the
  default non-root workload, and the workload's own dependencies. A writable
  `mounts:` entry containing the template is refused, for the same reason as one
  containing the recipe: the next box built from it would boot what the guest
  wrote.
- **mounts**: host directories exposed at absolute guest paths. Nothing is shared
  unless it is listed here: a recipe with no `mounts:` boots a sandbox with no
  host filesystem in it at all.
  A mount may not contain `~/.terra`, and terra refuses the recipe if it does.
  It holds things that decide what the sandbox *is* — a box's `recipe.yaml` is
  its mount list and egress policy; `~/.terra/cache` holds the kernel and the
  init agent every box boots — and a share carries your own write access to
  them, so a guest that could reach either one would be choosing the rules of
  its next boot. Since a box's own state lives under `~/.terra/box`, sharing
  the project directory itself is fine — nothing of the box's is in it. The
  refusal bites only for `~/.terra`; share a subdirectory (`host: ./src`) if
  you need it anyway. A `storage.boxes` or `storage.cache` moved out of `~/.terra` by
  `config.yaml` is refused in its own right, wherever it now is.
- **volumes**: empty, fixed-size ext4 disks created on the host and mounted at
  absolute guest paths — like a tmpfs with a hard size, but on disk and
  persistent per box (survives restart; wiped by `terra rm`). Unlike `mounts`
  (which share existing host dirs), a volume is fresh storage the guest owns;
  `size_mib` is a hard cap enforced by the kernel (writes past it get ENOSPC).
  Distinct from `hw.rootfs_mib`, which caps the writable rootfs. The `name` is
  what keys the image, so renaming a volume — or dropping it from the recipe —
  starts a fresh one; the old image is kept, with a line saying so, until
  `terra setup --rebuild` or `terra rm` removes it.
- **env**: environment variables exported for the workload and hooks.
  `env_file:` names a dotenv-style file merged on top (the file wins, and a name
  set in both is warned about); a relative path is the box project's, `KEY=VAL`
  lines only, the value taken literally — quotes included, and a shell `export`
  prefix refused rather than silently exporting a name nothing can read.
  **Note for docker-compose and `.env` loaders:** those strip surrounding
  quotes, and terra does not. `TOKEN="abc"` exports the five characters
  `"abc"`, not `abc` — write `TOKEN=abc`. Nothing is unquoted, expanded or
  interpolated, so a value means exactly the bytes after the first `=`.
  Values reach the guest inside the boot plan, over a socket, and land only in
  the process environment — never written to a file, including the sandbox
  description at `/terra/README.md`, which names the variables that are set
  without repeating their values (that file lives in the box's *persistent*
  filesystem, so a value there would outlive both the boot and the recipe line
  that set it). That is what makes this a reasonable place for sandbox secrets.
- **network**: two modes, deliberately, and they differ in exactly one thing:
  what is reachable *without* a rule naming it. `allowlist` — **the default** —
  reaches nothing; `unrestricted-public` reaches any *public* address. Rules mean
  the same in either, so `allow`/`hosts` are read in both — under
  `unrestricted-public` they are how a recipe reaches the host's LAN and other
  private addresses, which neither mode opens on its own. Each `allow` rule is a
  bare string: a DNS name or an IP/CIDR literal, with an optional `:PORT`
  (`[v6]:port` for an IPv6 literal); no `:PORT`
  means any port. **A name is exact**: `example.com` grants that name and nothing
  else. Its subdomains are opted into with a leading `*.` — `*.example.com`
  covers `api.example.com` and `a.b.example.com`, on label boundaries only (so
  not `notexample.com`), and deliberately *not* `example.com` itself; list both
  to get both. The subtree used to come with every name whether the recipe wanted
  it or not, which left "only this host" unwriteable and made the wide grant
  invisible — one `api.mycorp.dev` entry quietly forwarded every
  `<anything>.api.mycorp.dev` upstream, which is a data channel out of a box
  meant to have none. No other spelling of `*` is accepted. The port is enforced at connect time
  (a `:443` rule denies `:80` to the same host). A *name* rule opens nothing under
  `unrestricted-public` unless a `hosts:` record publishes that name: public
  names already resolve and connect there, and a name resolved *upstream* can
  never open a local address — that is what stops a hostile answer from pointing
  one there. A name rule with no record behind it is refused rather than left
  reading as a grant; write the address itself (`allow: ["10.0.0.5:445"]`),
  publish the name with a `hosts:` record and keep the rule, or use
  `mode: allowlist`, where a name rule gates public egress. There is no one-boot
  override: the mode is the recipe's, so widening it is an edit somebody
  re-approves rather than a flag on the command line.

  **No rules means no network**, and that is the default a profile gets by saying
  nothing: an allowlist with an empty `allow` and no `hosts` reaches nothing at
  all — DNS included, so there is no resolver left to leak names through. Opening
  a sandbox up is always an explicit line in the profile.

  **An allowlist gates names too**, not only addresses: a query for a name no
  rule lists is answered `NXDOMAIN` rather than forwarded, so the resolver is not
  a way to send data somewhere the connection filter would have refused. A rule
  naming an address grants that address — reach it by address; a sandbox that
  needs to *resolve* something lists the name.

  **Local space is closed until something names it.** In both modes terra pins a
  strict egress floor: the host, the host's LAN, and every
  RFC1918/CGNAT/link-local/multicast range are unreachable by default. The floor
  is set in code, not from the environment, so there is no config, CLI or env
  knob that lowers it — which is also why the wide mode is spelled
  `unrestricted-public`: it lifts the default reach, not the floor.

  What the floor will not overrule is a destination written down: an `allow`
  entry covering an address (`allow: ["10.0.0.5:5432"]`, or a range like
  `allow: ["10.0.0.0/24"]`) reaches it, in either mode, on the port it names. The
  floor is there to stop a box drifting onto the network it happens to be running
  on; it has no business vetoing the recipe. Note what that means for the widest
  spelling: `allow: ["0.0.0.0/0"]` really does hand over the LAN, the host's
  loopback and the cloud metadata service, so write the range you mean.

  A **DNS-learned** address is the exception: that is an upstream resolver's word
  rather than the operator's, so it stays under the floor — honouring it would
  make DNS rebinding a way in. A `hosts:` record is not that: the address is one
  *you* wrote, so a rule naming the record opens it like any other.

  **What the allowlist is not.** It is a deny-by-default egress filter for
  short-lived agent sandboxes, not a general-purpose firewall. Name rules work by
  learning IPs from allowed DNS answers, so if an unrelated host is co-hosted on
  an IP learned for an allowed name, the guest can reach it by dialling that IP
  directly. Deny-by-default on *unlearned* IPs still holds, as does the floor.
- **hosts**: DNS records the gateway answers itself instead of forwarding the
  query upstream — a name and the address it resolves to, and nothing else. Write
  `addr: HOST_LOOPBACK` for the machine terra is running on (the guest cannot
  dial the host's loopback: `127.0.0.1` there means the guest, so the record
  answers with the gateway's own address and the gateway dials the loopback), or
  any address the host can reach.

  A record is **not** a grant. It says where a name points; `allow:` says what may
  be reached there, exactly as it does for a name an upstream resolver answered.
  The host can also be opened without a name for it, with `HOST_LOOPBACK` in
  `allow:` — and that token, or a record resolving to it, is the *only* way in:
  no address rule reaches the host, however wide.

  ```yaml
  hosts:
    - {name: db.local, addr: HOST_LOOPBACK}
  allow:
    - db.local:5432        # …without this, the name resolves and connects to nothing
  ```

  Records sharing an address share what is opened there — two `HOST_LOOPBACK`
  records both resolve to the same address, so a port opened through one name is
  reachable through the other. That is how DNS and address-based filtering have always
  composed, and terra does not invent a distinction the network itself does not
  make. Scope by port, not by hostname.

  A record's name is answered locally and never forwarded, so
  `{name: api.example.com, addr: HOST_LOOPBACK}` does **not** make
  `anything.api.example.com` resolvable — the subtree stays `NXDOMAIN`, and a box
  with an otherwise empty allowlist keeps having no way to reach a resolver.
- **ports**: publish a guest listener back to the host. Each entry is
  `"HOST[:GUEST]"` (bare `"8080"` = `8080:8080`); the gateway binds
  `127.0.0.1:HOST` on the host and forwards to `GUEST` inside the guest (the
  workload must be listening there). Bound to loopback only — not the LAN — so
  the guest is reachable from the host but stays isolated from the wider network.
- **hooks**: `on_create` is the one-time setup, baked into the box's own
  filesystem when it is built (by `terra setup`, or by the first boot) and
  skipped on every boot after — the guest keeps the stamp that decides this, at
  `/terra/recipe`. Every bake runs in a VM with no mounts attached at all, so
  it genuinely cannot reach a host directory — which matters, because
  `on_create` is where `npm ci` and friends run third-party build scripts as
  guest root. `on_start` runs inside the guest before the
  workload on every boot; `pre_stop` runs on orderly shutdown (Ctrl-C / SIGTERM)
  before exit.
- **workload**: the program to run. `entrypoint` + `args` are passed literally
  to the guest exec (argv = `[entrypoint, ..args]`). For a shell command use
  `entrypoint: /bin/sh, args: ["-c", "echo hi"]`. Defaults to an interactive
  `/bin/sh`. Runs as `terri` (uid 1000) unless `--root`. `workdir` says where
  it starts, as an absolute guest path — it need not be a mount: it is created if
  missing and owned by the workload user. Unset, the workload starts in the home
  of the user it runs as (`/root` under `--root`, `/home/terri` otherwise).
  Either way the boot fails if the directory cannot be created or entered, rather
  than starting somewhere else and resolving the workload's relative paths
  against the wrong tree.

- **sudo**: commands the workload user may run as root. Each entry is a bare
  command name, permitted with any arguments:
  ```yaml
  sudo: [apk, rc-service]
  ```
  Both `doas apk add git` and `sudo apk add git` then work (`doas` is baked into
  the image, with Alpine's `sudo` shim beside it); anything not listed is
  refused. The policy is regenerated from the profile on every boot, so deleting
  an entry revokes it on the next start even though the rootfs persists. Ignored
  under `--root`, where the workload is already root.

The guest root filesystem is owned by root, as a Linux root filesystem should
be, so by default a `terri` workload cannot `apk add` or write outside
`/work`, `/tmp` and its volumes. **Hooks run as root** — that's where one-off
package installs belong: `on_create` for expensive setup baked into the box,
`on_start` for every boot. Use `sudo:` when the *workload itself* needs to
elevate, and `--root` to run the whole thing as root.

Note this is ergonomics, not a sandbox boundary: what isolates the **host** is
the VM, so guest-root is not an escape. `sudo:` exists to keep an agent from
casually trashing its own rootfs, not to contain a hostile one.

What the guest cannot do is go around it through the agent. The agent runs as
PID 1 and serves two vsock ports — the session (a joining `terra [BOX]`) and files
(`terra put`/`get`) — and the guest kernel has vsock loopback, so those ports are
dialable from inside the sandbox. They accept the **host** and nobody else: a
connection from any other CID is dropped on accept, unread. Without that check a
workload could write any file as root, read one back, and join its own terminal
session, which would leave `sudo:` deciding nothing.

Press **Ctrl-C** to interrupt the workload, or `terra stop` for an orderly
shutdown from elsewhere — as does `systemctl stop`, whose SIGTERM lands in the
same place: the guest stops the workload — SIGTERM, then
SIGKILL five seconds later, since an interactive shell ignores SIGTERM — runs
`pre_stop`, and exits. No VM is left running either way.
