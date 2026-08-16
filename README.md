# Terrarium

A KISS microsandbox for isolating AI agents, built on [libkrun](https://github.com/libkrun/libkrun).

One minimal shared Alpine rootfs, a YAML config, host-path mounts, guest-side
hooks, and a deny-by-default network egress allowlist enforced by an
in-process userspace network gateway.

## Prerequisites

- **libkrun, libkrunfw and smolvm are vendored submodules** — libkrun as
  [`cryi/libkrun`](https://github.com/cryi/libkrun) (a mirror of upstream, so
  host-portability patches have somewhere to live and to be sent upstream from;
  it currently carries none), libkrunfw pristine, built from source for its
  guest kernel, and [`cryi/smolvm`](https://github.com/cryi/smolvm) for its
  `smolvm-network` crate, the egress gateway. All folded into a single
  fully-static `terra` binary. After cloning:
  ```sh
  git submodule update --init   # not --recursive: see vendor/README.md
  ```
- **`zig`** on the build host — it provides the musl C cross-toolchain
  (`scripts/zig-musl-*`), so no musl gcc need be installed.
- **KVM** (`/dev/kvm`) on Linux.

At **run** time terra needs nothing else — no network, no `curl`/`tar`, no
e2fsprogs. The guest root filesystem is prebaked into the binary at build time,
so creating a box is a decompress plus a `set_len`; the filesystem work that
needs Linux (growing the image to `hw.rootfs_mib`) happens inside the guest, which
is always Alpine. That is also what lets a non-Linux host create a box.

The **build** host additionally needs `curl` + `tar` + `unshare` (to fetch and
bake the base rootfs) and downloads a pinned, hash-verified e2fsprogs release to
build the static `mke2fs`/`resize2fs` that get baked in.

## Build

```sh
make build     # vmlinux + prebaked rootfs/boot images + static terra binary
make verify    # cargo fmt --check + clippy -D warnings + full test suite
make dist      # -> dist/terra, one fully-static portable binary
make cross     # cross-compile the host binary (see Platform support)
make clean
```

`terra` is a static-musl PIE binary — `ldd` reports *not a dynamic executable*.
Always use `make dist` to build it; the binary is gitignored.
It links **nothing** at runtime (no libc, no loader, no `.so`) and runs on any
Linux with KVM. libkrun is a mainline Cargo dependency (unmodified); the guest
kernel is libkrunfw's `vmlinux`, embedded and booted as an external kernel —
no dlopen, no patch. It ships stripped and gzipped, and is unpacked once into
`~/.terra/cache/vmlinux-<hash>` (the name is the hash of the embedded bytes, so
later boots reuse it and a terra upgrade prunes the one it replaces).

> Building libkrunfw compiles a full Linux kernel (needs `flex`, `bison`, `bc`,
> `libelf`, `openssl` dev headers, and Python `pyelftools`) — slow on first
> build, then cached.

## Usage

A box belongs to a directory and has a name. `setup` reads a recipe and builds
the box from it, `terra <box>` uses it, `rm` throws it away — and every command
defaults to the directory you are standing in and to its only box:

```sh
$ cd ~/code/app
$ terra dev setup                 # pins the recipe, builds the guest
$ terra                           # boots it (or joins it, if it is up)
$ terra -d                        # or headless, in the background
```

**The box comes first, always.** `terra <box> <verb>` is the whole grammar:
there is no verb-first spelling to remember and no verb that reverses it, so
`terra dev setup` and `terra dev stop` read the same way round. (`ls` is the one
exception, and it is not one: it asks about the *directory*, not a box.) Both
halves are optional — the verb, because using a box has none, and the box,
because it defaults to the directory's only one.

The verbs split along one line, and it is the line the security model rests on:
**`setup` is the only command that pins a recipe.** Everything else — using a
box, `stop`, `put`/`get`, `logs` — works on the copy `setup` pinned inside the box.
(`show` may read a recipe and the bare form can offer a setup, but neither
pins one that a person did not answer for.) So editing a recipe, or anything a
guest may have done to one inside a share, changes nothing until `terra setup`
runs again. (`terra setup` also sets up a *box*; the one-time host setup terra
itself needs is in [`packaging/README.md`](packaging/README.md).)

**Using a box has no verb at all.** `terra dev` boots it, or joins its terminal
if it is already up — because which of those you want is a fact about the box,
not a decision you should have to make and can get wrong. There is no `start`
and no `attach`; they were one intent wearing two names.

That does mean box names and terra's own words share one namespace, so terra's
own words are reserved: a box cannot be called `logs` or `stop` — `terra logs`
is the log viewer, always, and a name it could silently shadow is refused
before anything is built under it. A short list of words a *future* verb might
take (`run`, `status`, `restart`, `init`, …) is held for the same reason: the
day one of them ships, a box already wearing that name would become
unaddressable. Every other name means the same box everywhere it is written.

The box before `setup` may be a recipe **path** as well as a name — an entry in
the project's `terra.yaml` (see below), or a file — because a recipe path is not
a box yet. A box made from a path is named after the file's stem.

```sh
terra dev setup                  # the box "dev", from its terra.yaml entry
terra ./sandbox.yaml setup       # the box "sandbox", from that file
```

One directory can hold several boxes — same working tree, different sandboxes —
and every command takes the name to say which one. With one box the name is
never needed; with several, a bare command refuses to guess and lists them:

```sh
terra dev                        # boot the box "dev" (or join it)
terra ci -- make test            # while "ci" runs the tests
terra ci logs -f
terra dev stop
```

`terra setup` does the expensive part up front: it bakes `on_create` in a VM
with **no shares attached at all**, which is what makes "`on_create` cannot
reach a host directory" true rather than merely intended. Every bake runs in
that same isolated VM — a first boot that finds a fresh filesystem runs one
before the workload VM starts — so which command you typed never changes the
sandbox the recipe's build scripts see.

You do not have to call `setup` first, though. A bare `terra dev` on a box that
has a recipe somewhere but was never built shows you what that recipe grants —
its mounts, its egress posture, any host file it reads for `env_file:`, anything
it runs as root — and offers to build it. Answering `y` is the same act `terra setup` performs, which is why the offer
carries the same information and the same warning when the recipe sits somewhere
a sandbox could have written it. **With no terminal there is no offer**: a script
gets an error naming `terra setup`, because deciding to pin a policy is not a
thing that should happen to someone while they are looking elsewhere.

```sh
# one-shot: a command instead of the recipe's workload (argv after `--`)
terra -- npm test
terra -- sh -c 'make && ./run'

# hardware, environment and egress come from the recipe, not from flags: what a
# box may reach is the thing `terra setup` pinned and someone approved
terra show                       # the fully-resolved recipe a boot would use

# an interactive start is detachable: Ctrl-\ hands the terminal back and the box
# keeps running

# or run headless from the start, then manage it
terra -d                         # background; prints a pid
terra logs -f                    # follow the box's diagnostics
terra                            # join its terminal (the escape key detaches)
terra stop                       # graceful stop (runs pre_stop)
terra ls                         # created? running? (details: terra show)
```

**Your project directory stays yours.** Everything terra owns for a box lives
outside it, in `~/.terra/box/`: one directory per project (named for it, plus a
hash of its path), one subdirectory per box:

```
myproject/                            # your files, and nothing else

~/.terra/box/myproject-8454e10d1c72dd5a/
    ├── .path             # which directory these boxes belong to (`terra ls` reads it)
    └── dev/              # one directory per box name — a box only ever has the one you gave it
        ├── recipe.yaml   # what this box was created from — the only file you write
        ├── rootfs.img    # the guest's root filesystem (bounded ext4)
        ├── vol-data.img  # one per `volumes:` entry, keyed by its name
        ├── c             # control: the guest's only channel to terra (plan + stop)
        ├── a             # the agent's port: every session, `terra put`/`get` and `terra exec`
        ├── terra.pid     # the VM process — `terra stop` signals it, and the lock on it is what keeps one VM per box
        ├── baking        # present only while an `on_create` bake holds the box
        ├── terra.log     # the box's diagnostics: terra's, libkrun's, the gateway's, the guest's boot and hooks
        └── terra.log.1   # the generation terra.log last rolled off (see *Logs*)
```

It is out of the tree because of what a share means. A mount hands the guest
your own authority over that path, and `recipe.yaml` *is* the box's security
policy — what it may mount, what it may reach, what it runs. So a box whose
state sat inside the directory it shared could rewrite the rules of its own next
boot, and terra refused the recipe. That made the most ordinary thing a
developer wants — "sandbox this project, working directory and all" —
impossible to write. Moving the state out is what makes `host: .` an ordinary
mount:

```yaml
mounts:
  - host: .          # the box's own directory, shared whole
    guest: /work
```

The project directory's name is `<its name>-<hash of its full path>`: the name
so `ls ~/.terra/box` reads as something, the hash because two projects called
`app` are ordinary. The path is resolved first, so reaching one project through
a symlink addresses the boxes it already has rather than quietly making a second
set. The `path` file is the way back — nothing else could say which project
`myproject-8454e1…` belongs to, and it is what `terra ls` prints.

Under `~/.terra` rather than beside the project, for three reasons: terra already
refuses to share `~/.terra` with any sandbox, so every box on the machine
inherits a rule that was already there; the parent of a project is not
necessarily yours to write in (`/srv/app`, a home directory, a read-only
checkout); and the path is short — which matters, because a unix socket path
cannot exceed 107 bytes (103 on macOS), a fixed array in the kernel's
`sockaddr_un` that no host can raise, and the box's own path is spent from that
same budget. A deeply nested project used to pay for its own depth and could be
refused outright; a box of `~/.terra/box` never comes close.

The single-letter socket names date from that budget, and they are two because
they are two *directions*: `c` runs guest→host (terra binds it, so the plan and
its secrets stay in memory and the socket is `0600`), while `a` runs host→guest
— every session, `terra put`/`get` and `terra exec` connection, told apart by a service
byte — and is bound by libkrun.

**Recipes are read at `setup`, never anywhere else.** The pinned copy inside the
box is what boots; a recipe file — even one sitting inside a read-write share —
is just bytes until a host-side `terra setup` pins it. That is a property of the
CLI's shape rather than of a check somewhere: no command except `setup` takes an
argument that names a file, so no other command has a path through it that could
pin one.

And `setup` itself asks. If the source lies inside a directory some box of this
directory shares read-write, its guest may be the author — so terra prints what
the recipe would grant (its mounts, its egress posture, any host file it reads
for `env_file:`, anything it runs as root) and waits for a `y`. With no terminal to ask on — a script, CI, a systemd unit —
it refuses instead, naming `--trust-recipe` as the way to say yes in the script's
own text.

`--trust-recipe` is *only* that yes. Rebuilding the guest filesystem is
`--rebuild`, a separate flag: those were one flag once, which priced "I have read
this edit" at the whole box, and a check that expensive is one people learn to
route around.

Not to be confused with `~/.terra` itself, which is terra's own rather than any
box's: the reusable recipes, and the kernel and boot-volume cache shared by every
box on the machine.

**Moving the heavy data: `~/.terra/config.yaml`.** The two directories that grow
are the boxes and the payload cache, and a laptop whose home is on a small disk
does not want either. One optional file moves them:

```yaml
# ~/.terra/config.yaml — both keys optional, absolute or ~/…
storage:
  boxes: /mnt/ssd/terra/box
  cache: /mnt/ssd/terra/cache
```

Each key names what is kept there rather than the directory's default name,
which is the half that changes. Nothing else changes: terra creates each as `0700` wherever it now is — an
external disk is commonly mounted world-readable, so neither leans on the
permissions of whatever it was pointed into — and refuses to share either with a
sandbox, exactly as it refuses `~/.terra`. Boxes that already exist stay where
they are; move them yourself, or set the boxes up again. A file terra cannot act
on is an error rather than a fallback to the defaults, since answering with the
old directory would read as a machine with no boxes on it.

### The manifest: `terra.yaml`

A project that wants its boxes named and shared commits a **manifest** at its
root — box names mapped to recipes, so `terra dev` means the same sandbox
for everyone who clones it:

```yaml
# terra.yaml
boxes:
  dev: ./dev.yaml      # a recipe in the repo
  ci: ~/ci/terra.yaml  # or anywhere a path reaches
```

A bare `terra setup` in a directory with no boxes yet uses the manifest's only
entry — or, with several, lists them rather than guessing.

Entries are **references only**, deliberately not recipes-in-place. The
manifest lives in the project root, which is exactly what a box shares, so a
guest may be able to write it. A pointer can at worst repoint a name at another
recipe file, and every road from there is covered: a reference into `~/.terra`
is a file no share can ever contain (terra refuses to mount `~/.terra`
anywhere), and a reference to a file inside the share is asked about at
`terra setup`. A recipe written in place would have been a whole policy a guest
could author; a pointer is not.

That question is asked about a box being set up for the **first** time too,
which is the case the manifest actually reaches: a guest can name a box that does
not exist yet, and a box that does not exist has no recipe of its own to judge an
edit against. So `setup` asks every pinned recipe in the directory — the sibling
box that granted the share is the one that answers. And a bare `terra <thatname>`
pins nothing on its own: with no terminal it says the box has never been set up,
and with one it shows the recipe and the warning and waits for a `y`.

### Commands

One VM runs per box. Every command addresses a box as `[BOX]` — its name —
defaulting to the directory's only box:

| command | does |
|---------|------|
| `terra [BOX] setup` | **the one command that pins a recipe source**: pin it to the box, unpack the filesystem, bake `on_create`. BOX is a box of the directory — from `terra.yaml`, or a recipe path — and defaults to the directory's only box. `--trust-recipe` answers its question in advance, `--rebuild` rebuilds the filesystem. `--dry-run` runs every refusal this setup would raise and stops before it changes anything — nothing pinned, no filesystem built, no hook run — exiting 0 if the setup would go through and non-zero with the refusal if not, so a CI step is `terra <box> setup --dry-run`. It resolves the recipe the way the setup it stands for does, which is why it is a flag here rather than a verb of its own: a separate check would answer about the pinned recipe while `setup` pinned the one `terra.yaml` names. The other two flags decide what a setup *does*, the half a dry run skips, so neither can be written alongside it. Booting is `terra <box>`'s job |
| `terra [BOX]` | **use a box** — boot it, or join its terminal if it is already up. There is no `start` and no `attach`: which one you want is a fact about the box. A boot that runs to the end exits with the workload's own status, as `docker run` does. `-d` boots headless; the escape key (default Ctrl-\) detaches and leaves it running. A box that was never set up is offered one, on a terminal only. A box whose `on_create` bake is running holds its lock without having a session to join, so this says so and stops rather than waiting on a terminal that is not coming |
| `terra [BOX] exec [--root] -- CMD…` | run one command in a running box, and exit with its status. Runs as the workload's user; `--root` runs it as root **without granting the workload anything** — the command comes from the host over a port nothing inside the guest can reach. A terminal is allocated exactly when this end has one, so `terra dev exec -- sh` is an interactive shell and `terra dev exec -- cat f > out` writes plain bytes with nothing to remember; `-t`/`-T` say so outright, for a script driving something that insists on a PTY or one that wants exactly the bytes a redirect would get. `--agent-timeout SECS` bounds the wait for the box's agent |
| `terra [BOX] put SRC DST` / `terra [BOX] get SRC DST` [`--agent-timeout SECS`] | copy one file in (`put`) or out (`get`) of a running box. The verb says which side is the box's, so neither path needs a marker: the box's side is an absolute guest path, the host's is whatever your shell hands over. `get` into a directory keeps the file's own name. One file at a time — a directory is a mount's job |
| `terra [BOX] stop` [`--wait SECS`] | orderly stop: `pre_stop`, then the VM exits; a box still up after 30 s (or the `--wait` value) has its VM killed. Stopping a stopped box succeeds — it is already what was asked for |
| `terra [BOX] rm` [`--purge`] [`--force`] | throw the box away, keeping its recipe (`--purge` takes that too; `--force` removes a running box — it is asked to stop first, waited on for 30 s or the `--wait` value, and killed if it does not go, since what is being removed is the filesystem it is still writing to). `--wait` only means anything alongside `--force`, so it is refused on its own |
| `terra [BOX] storage <show\|export\|import\|prune>` | the box's images — its guest filesystem and volumes. `show` lists them with what each is sized to and what it actually costs on disk (they are sparse, so the two differ a lot), marking any the recipe no longer names; `export FILE` writes them all to one compressed file and `import FILE` replaces another box's images with them, so a box set up from the same recipe elsewhere gets this one's state; `prune` removes the volume images the recipe dropped, and their data with them. `export` and `import` take the box's lock, so neither runs against a live VM |
| `terra [BOX] show` [`--with-env-values`] | the fully-resolved config a run would use: the pinned recipe once the box exists, whatever the source it was pinned from says now. A recipe named by *path* is read as a file, which is how one is reviewed before there is a box. `env:` values print as a placeholder — this output is made to be redirected or pasted into a bug report — and `--with-env-values` is how you ask for them, which is also how you read back what an `env_file:` merged in. A recipe `terra setup` would refuse still prints, with a warning: reading one is what `show` is for, and `terra <box> setup --dry-run` is what answers that question outright, for the recipe that setup would actually pin |
| `terra ls` (`terra ps`) | created? running? — every box of the directory, with where each one's files are (details are `show`'s). `--all` lists every box on this machine instead, each with the directory it belongs to. `--tsv` prints one tab-separated line per box — state, name, directory, files — the format scripts may rely on |
| `terra [BOX] logs` [`-f`] | the box's diagnostics — terra's, libkrun's and the gateway's, plus the guest's boot and hooks. The workload's terminal is not here; that is what attaching shows (see *Logs*) |

Every one of them takes `--project DIR` to address a directory other than the
current one (`ls --all` spans them all anyway). A bare `terra [BOX]` on a box
already up offers to attach instead. `terra [BOX] -d` on one is a success — a
detached start asks for a running box, and it has one — and a start with
neither `-d` nor a terminal to attach from exits `125` (outside the workload's
own exit-code space), so a script can tell "already running" from "failed".

A boot that ran its workload to the end exits with **that workload's status**,
signals spelled `128 + signal` as a shell spells them. It travels out of the
guest over the control connection, because the VM itself cannot carry it: the
hypervisor exits with `0` however the guest ended. `-d` is the exception and
says so — it exits `0` once the box is up, since the workload has not run yet.

`terra ls` is the one command that is not about a directory you are standing in.
Because every box's files are in one place, it can simply list them, each by the
directory it belongs to:

```
$ terra ls
running      /home/me/code/app (dev)
setting-up   /home/me/code/app (nightly)
stopped      /home/me/code/app (ci)
not-created  /home/me/scratch/spike (default)
gone         /home/me/code/deleted-last-week (default)
```

`setting-up` is a box whose `on_create` bake holds it: a VM is up, but it has no
session and no agent port yet, so nothing can be run in it until the bake is
done (`terra <box> logs` follows it).

`gone` is a box whose directory no longer exists: nothing removes a box when a
project is deleted or moved, and it still owns a filesystem. `terra <box> rm --purge
--project <that>` clears one (and clears the project's entry once its last box is
gone).

**The rm/run cycle.** `terra rm` deletes the guest filesystem but keeps the
recipe, so `terra <box>` afterwards rebuilds the box from scratch — including
`on_create`, since the stamp that records it lives *inside* the filesystem that
was just removed. That is the whole reset story: `rm` then `terra <box>`.

**Storage travels; the recipe already did.** A box is a recipe plus what its
guest wrote, and only the second half needs moving — the recipe is committed
with the project. So `terra <box> storage export` writes the images alone, and
importing them needs a box already set up from that recipe:

```
$ terra dev storage export ./dev-state.terra   # here
$ terra dev setup                              # there, from the same recipe
$ terra dev storage import ./dev-state.terra
```

That keeps the security model whole: nothing an artifact carries can decide what
a box mounts, reaches or runs — pinning a recipe is still `setup`'s question and
nobody else's. An import replaces the images the artifact names and leaves the
rest where they are, saying which; `on_create` re-bakes by itself if the
imported filesystem was baked from a different recipe, because the stamp that
records the bake travels inside it.

### Logs

A box has one log, `terra.log`, and it is the box's *diagnostics*: terra's own
messages, libkrun's, the gateway's account of what it refused, and the guest's
console — the kernel, the agent, and every `on_create`, `on_start` and
`pre_stop` hook. `terra [BOX] logs` [`-f`] shows it.

What is deliberately **not** in it is the workload's terminal. That one is the
session's: the guest multiplexes it (see *the guest agent* below) and it reaches
whoever is attached, nobody else. So the two questions have two answers —
`terra logs` for *why is my box broken*, attaching for *what is it doing* — and
the first no longer arrives interleaved with an escape sequence from the second,
which used to corrupt a live TUI and every later replay of the log.

The split is one the guest already had: its diagnostics go to the console
(`hvc0`), the workload gets a PTY, and terra hands libkrun the log for the
console and nothing at all for the PTY. A bake has no say in this and needs
none — an `on_create` VM serves no agent port, so its output has only the
console to leave by, which is why `terra logs` follows a bake and why a failed
one can still be read with nothing attached.

The consequence worth knowing: **a detached run nobody attaches to leaves no
record of what it printed.** A workload that wants one writes it, to a volume
that outlives the box's filesystem anyway. Terra does not keep it for you: a
terminal is not a log, and a box that runs for a month would make it one.

`--foreground` is the one exception, and for the reason the mode exists. That VM
runs inside the terra process a service manager started, so the console *is*
that process's stdout and no client will ever attach to relay the workload —
there, the guest broadcasts its terminal to the console too (the plan's
`workload_on_console`), and terra moves its own output into the log once the
banner is said. A systemd unit gets the workload in its journal and the
diagnostics in `terra logs`, which is the same division by another name.

**The log rolls.** At 32 MiB the live file is copied to `terra.log.1` and
emptied in place, with a line saying where the rest went. Exactly one generation
is kept, so the log costs at most 64 MiB however much is written to it — which
matters because a guest can drive it: a refused connection is a line here.
`terra logs` reads both generations oldest first, so the seam does not show, and
`-f` follows across a roll rather than going quiet or repeating itself.

Copy-truncate rather than the cheaper rename, because libkrun *dups* the console
descriptor it is handed and writes to that copy for the VM's whole life: a
rename would leave the guest writing into the generation just rolled off, which
the next roll would overwrite. Every writer opened the file `O_APPEND`, so
emptying it puts all of them back at the front with no hole in between.

The log starts empty on every boot and takes the rolled generation with it, so a
box you restart often shows the run you are looking at rather than every run it
ever had.

Everything host-side is collected by one `tracing` subscriber, which is also
what makes the gateway's own account of a refusal visible at all — those events
were written to nobody for as long as terra installed no subscriber. `RUST_LOG`
sets the level (libkrun defaults to `warn`, the gateway to `debug`).

A boot that never gets off the ground is reported by the process that spawned
it: it replays the tail of the log rather than leaving you to go looking. (A
`--foreground` boot has no such parent, and needs none — nothing has moved off
its streams yet when a VM fails to start.)

**The guest agent is the guest init (PID 1).** The kernel starts it directly off
the boot volume; it fetches a boot *plan* from terra over vsock (see *How it
works*) and brings the guest up — mounts, NIC, hooks, privilege drop — then runs the
workload on a PTY and multiplexes it over vsock: every client — the launching
terminal and every later `terra [BOX]` — shares one view (all output broadcast, all
input forwarded), so an agent like *pi* can be observed and steered from several
places at once. A client attaching to a running TUI is repainted with the
current screen (via a vt100 screen model), not a corrupt scrollback replay. On
an orderly stop the agent runs `pre_stop` before the VM exits. The agent ships in
the boot volume image `make build` bakes, not in the host binary.

Bare-form flags: `--project <dir>` (the box, default cwd), `--root` (run the
workload as root instead of the default `terri` (uid 1000) — only the exec uid
changes; shares always map to the launching host user, so files land owned by you
either way), `-d/--detach`, `--foreground` (run the VM in this process — for a
service manager like systemd; a bare start with no terminal and neither flag is
refused rather than guessed at), and `-- <cmd> [args…]` (run this instead of the
recipe's `workload:` for one boot; argv is passed literally to the guest exec, so
use `-- sh -c '…'` for a shell line).

There is deliberately no flag for hardware, environment or egress. Those come
from the recipe alone, because a boot runs what `terra setup` pinned and someone
approved — a flag that widened what a box may reach would route around the one
page that question is ever put on.

Man pages for every command are generated from the CLI by `make man` (or any
`make verify`) into [`packaging/man/`](packaging/man/) (`terra.1`, `terra-run.1`,
…), together with the shell completions in
[`packaging/completions/`](packaging/completions/).

Where a `BOX` argument is accepted, a bare name is a box — a `terra.yaml`
entry, or one already set up; anything starting with `.`, `/` or `~` is a
recipe path, and names the box after its stem. A relative host mount path
inside a recipe is resolved against the directory the *box* belongs to, so the
same box shares the same directories from wherever it is addressed
(`--project` included).

## The recipe

One format, two ways to name one: a file by path (`terra ./ci.yaml setup`), or
an entry in the project's `terra.yaml` pointing at one. Either way, `setup`
copies it into the box as its pinned `recipe.yaml` — the copy every boot uses.

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

## Security model

**The boundary is the VM.** A hostile workload is contained by libkrun/KVM and
nothing else in this design is asked to hold it. Everything below is either a
deliberate hole through that boundary, or ergonomics inside it.

What crosses the boundary, because you asked it to:

- **`mounts`** — the listed host directories, read-write unless `readonly`.
  Writes land as *your* host user (the guest's uid 1000 is mapped to it), so a
  guest can do anything to those paths that you could — including creating real
  host symlinks in them. There is no host filesystem in a sandbox with no
  `mounts`. A mount that would contain `~/.terra` (this box's state or
  another's, and the kernel and agent every box boots) or **the terra binary
  itself** is refused when the recipe is read: those decide what the sandbox may
  mount and reach, what kernel it boots, and — for the binary, which an
  interactive or detached run re-executes to boot the VM — what the next run does
  at all, before there is a sandbox. They are not the sandbox's to write. A recipe
  *source* inside a share is allowed, because only `terra setup` reads one —
  and it asks first, showing what the recipe would grant, refusing outright where
  there is no terminal to ask on (`--trust-recipe` is the scripted yes). It asks
  about the first setup of a *new* box name too, since a box that does not exist
  yet has no recipe of its own to judge an edit against and `terra.yaml` lets a
  guest name one: the sibling box that granted the share is what answers.
- **`network.ports`** — a guest listener published on the host's `127.0.0.1`.
- **`allow: ["HOST_LOOPBACK[:PORT]"]`** — the only thing that reaches the
  machine terra is running on, together with a name a `hosts:` record resolves
  there. The host is not in the address namespace at all: no CIDR reaches it,
  `0.0.0.0/0` included, and neither does a mode's default reach.
- **`terra exec`** — one command in a running box, over a socket only the host
  can reach. It runs as whoever the workload runs
  as; `--root` runs it as root. That grants the *host* nothing new — the file
  service already writes any guest path as init, so a copy over a root-owned
  binary was always a way in — and it deliberately grants the *workload*
  nothing: a `sudo:` entry hands uid 1000 a standing escalation it can use
  whenever it likes, while an exec cannot be reached from inside the guest at
  all. Use `--root` for the things root is actually needed for (`apk add`,
  reading a root-owned log, `strace`) instead of widening `sudo:` for them.
- **`terra put` / `terra get`** — one file in or out, acting as guest root, over a socket only
  the host can reach. A file copied *out* keeps its permission bits so a script
  stays executable, minus setuid/setgid/sticky and group/world write: the guest
  chooses that file's contents, so it does not also get to leave a setuid binary
  — or one any other account can rewrite — owned by whoever ran the copy.
  Neither end follows a symlink at *any* component of the host path — the file
  itself or a directory above it — so a link the guest planted in a share fails
  with `ELOOP` instead of redirecting the copy into your `~/.ssh`. That is
  `openat2`'s `RESOLVE_NO_SYMLINKS`, which refuses the resolution in the kernel
  rather than checking a component and then opening it; `env_file:` is read the
  same way, for the same reason. (`O_NOFOLLOW` alone is not this: it covers the
  last component only, and the last component is not the shape of the attack.
  Off Linux — where no host boots a VM yet — the leaf is still all that is
  refused.) A copy out is capped at 8 GiB however long the guest says its file
  is, and both directions time out rather than waiting forever on a guest that
  has stopped answering.
- **`env:` values** — they travel in the boot plan over vsock and land in the
  workload's environment. They are never written to a file on either side, and
  the guest's own `/terra/README.md` names the variables without their values.

What does not cross it, in any configuration:

- **The host's own network, unless the recipe names it.** The egress floor is
  pinned to strict, so loopback, the host's LAN, every private range, link-local
  (cloud metadata) and the gateway's CGNAT range are unreachable by default —
  under `mode: unrestricted-public` too, and regardless of a learned DNS answer
  pointing there. That mode lifts the allow-list, not the floor, which is what
  its name says: *public* egress. An `allow` entry covering an address is the
  one thing that crosses it, because that is an operator writing it down.
- **The agent's vsock port.** The one port every session, `terra put`/`get` and
  `terra exec` connection arrives on is dialable from inside the guest (the
  kernel has vsock loopback), and its services act with init's privileges — so
  it accepts the host's CID and drops every other peer unread, and the agent
  claims it before any other guest code runs. The exec service matters most: a
  workload that owned the port could not gain privilege (it would be answering,
  not calling), but it could lie convincingly about what a `terra exec` found —
  in the one situation exec exists for, looking into a box you have stopped
  trusting.
- **The boot plan.** The host stops listening on the control port the moment the
  agent has dialled it, so nothing in the guest can ask for a second copy.

What is **not** a boundary, and should not be relied on as one:

- **Guest root.** `sudo:`, the `terri` user and the root-owned rootfs keep an
  agent from casually trashing its own box. They do not contain a hostile one —
  see the `sudo:` discussion above. The guest kernel is hardened against the
  workload-to-root hop (`kernel/terrarium-hardening.config`), but *hardened*
  is the right word and boundary is not: unprivileged user namespaces are
  available inside the box, because rootless `podman` is that mechanism rather
  than a consumer of it, so the distance from the workload user to guest root is
  a kernel bug. That is a deliberate trade, and it costs nothing the VM was not
  already covering.
- **Hooks.** `on_create`, `on_start` and `pre_stop` run as guest root, by design.
- **Running terra as host root.** Refused outright when any mount is writable.
  Root gets no idmap — real ids pass through virtiofs — so it acts as *real*
  root and the guest picks the owner, mode and setuid bit of everything it
  writes to a share — the sandbox inside out. Run terra as an unprivileged user in the
  `kvm` group (see `packaging/README.md`), mark those mounts `readonly: true`,
  or set `TERRA_ALLOW_ROOT=1` if you genuinely mean it.
- **The recipe itself.** A recipe can mount any host path read-write and run any
  command in the hooks, so it is trusted input: read one before `terra setup`
  the way you would read a shell script before running it. This matters most for
  the obvious case — sandboxing a repository that ships its own recipe.
- **Your terminal.** A sandbox's output reaches it byte for byte, escape
  sequences and all — that is what makes a TUI inside the box work, and it is
  what joining a session is for. A workload can therefore drive
  whatever its reader's terminal emulator implements: OSC 52 clipboard writes,
  title set-and-report, hyperlinks. This is the same deal `ssh`, `docker attach`
  and `kubectl logs` offer, and the answer is the same one — a terminal that
  does not enable those sequences — but it is a surface the VM boundary does not
  cover, so it is named here rather than left implied.

On the host side, a box's own directory is `0700` and everything terra creates in
it is owner-only. The agent socket is bound by libkrun rather than terra, under a
process umask libkrun clears for its own reasons partway through a boot — so the
`0700` directory is what keeps another account off it, and its services act as
guest root, so that mode is not a detail. The log carries the guest's boot and
its hooks; the rootfs image carries everything the guest ever wrote.

`~/.terra` is `0700` on the same terms — and so are the box and cache
directories, each in its own right, since `config.yaml` can put either on a disk
mounted for everyone. Checked on every run rather than only when terra creates
them: a directory left open by an older version, or by a looser umask, is
tightened, and terra refuses to run if it cannot be. That is not
housekeeping — the reusable recipes live there, and a recipe is the policy for
what a box mounts and what it may reach, next to the cache holding the guest
kernel and the PID-1 agent every box on the machine boots. Another account able
to write there picks all of it.

What actually enforces the isolation is three dependencies, so it is worth being
explicit about how they are pinned: all three are git submodules pinned by commit
— libkrun (`vendor/libkrun`, an unpatched mirror of upstream), libkrunfw
(`vendor/libkrunfw`, pristine) and the egress gateway
([`smolvm-network`](https://github.com/cryi/smolvm), `vendor/smolvm`). The
gateway is vendored rather than pinned by Cargo revision because it is the code
that decides what a sandbox may reach: that belongs in the same review as the
policy that configures it, not behind a version bump — that review is what found
the two hard-floor gaps fixed upstream in `d2573ac`, which this pin includes. All
three checkouts are unmodified; see [`vendor/README.md`](vendor/README.md). The build inputs that are downloaded
rather than pinned by commit — Alpine's minirootfs, e2fsprogs, doas — are all
verified against a SHA-256 in the Makefile.

## Platform support

The host binary is cross-built with [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild)
(`make cross`); the guest is always x86_64 Alpine Linux, so the guest agent and
the prebaked images stay Linux whatever the host is.

| target | state |
|--------|-------|
| `x86_64-unknown-linux-musl` | supported — builds, boots, e2e green |
| `aarch64-apple-darwin` | compiles end to end; the final link needs the macOS SDK for the `Hypervisor` framework (set `SDKROOT`) |
| `x86_64-apple-darwin` | libkrun has no Intel-Mac hypervisor backend (its HVF code is aarch64-only), so this needs work upstream that is not a packaging fix. libkrun on macOS is Apple Silicon only |
| `x86_64-pc-windows-gnu` | terra itself compiles (verified against libkrun's declared Windows API); libkrun does not. See below |
| `aarch64-unknown-linux-musl` | blocked upstream: libkrun calls `libc::statx`, which the `libc` crate does not expose for this target |

**Windows** is a libkrun question, not a terra one. Upstream ships the WHP API
bindings, the console handles and a complete `fs/windows` passthrough, but the
VMM never drives WHP (`vmm/src/` has `linux/` and `macos/` only, and
`device_manager/` has no `whp/`), and the vsock and virtio-net backends are
`nix`-only. Three dependency-level blockers sit underneath that: `krun-cpuid` is
declared for all of x86_64 though it needs KVM, `vm-memory`'s `rawfd` feature is
enabled unconditionally though the crate hard-errors on Windows, and
`linux-loader` pulls `vm-memory` with default features so that `rawfd` cannot be
turned off downstream — the last one wants a PR to rust-vmm.

None of that is in terra's way: its own sources are Windows-clean, so the day
libkrun's device and VMM layers land, the port is a dependency bump.

One thing in terra is Unix-only, and knowingly: **stopping a box is a signal.**
`terra stop` sends `SIGTERM` to the pid in the box's `terra.pid`, which the VM
process's handler turns into the one-byte stop on the control connection — the
same path `systemctl stop` takes, which is why there is only one. Windows has no
equivalent: `TerminateProcess` is `SIGKILL` with no `pre_stop`, and console
control events only reach a process sharing the console, which a detached VM does
not. That port will need a signalling channel of its own for the graceful half —
a named event a thread waits on, standing in for the handler that writes the
stop byte here — with the hard kill left to `TerminateProcess`. The note lives
on `sys::signal_pid`.

That pid lives in the file the box's lock is taken on — one file, so a pid read
under a held lock is that holder's by construction rather than by anyone
remembering to sweep a stale one. Nothing but `terra rm` ever unlinks it: the lock
is on the inode, so replacing the file would leave the next `terra` locking a
different one. This is the second thing a Windows port has to look at — a
`LockFileEx` range is *mandatory*, so while the lock is held nothing else can read
the file at all; locking a range past the end of the file is the way to keep the
pid readable there.

Everything else where the hosts genuinely differ lives in one module,
[`crates/terra/src/sys.rs`](crates/terra/src/sys.rs)
— unix sockets (std has them on Unix, `uds_windows` on Windows), file modes, and
the SIGINT/SIGTERM stop handler. Everything else is plain std: the box lock is `File::try_lock`
(`flock` on Unix, `LockFileEx` on Windows), a run spawns a background copy of
terra rather than `fork`ing (an interactive run then attaches to it, which is
what makes detaching possible at all), `terra logs -f` follows the file itself rather than shelling out to
`tail`, and the attached session drives the terminal through `crossterm`. The only
other `cfg` in the crate is in the libkrun FFI wrapper, where libkrun's own API
differs (console descriptors are kernel handles on Windows).

The filesystem work that genuinely needs Linux happens inside the guest.

## How it works

A box's guest root is a single bounded ext4 image, its `rootfs.img`, and terra
does not build it at run time: the image is baked at **build** time by the
Makefile (`mke2fs -d` writing the Alpine tree into it, inside a user namespace so
it lands root-owned) and shipped inside the binary, gzipped. Creating a box is
therefore a decompress plus a `set_len` — no mkfs, no privilege, no network, and
nothing fetched per machine — which is what lets a non-Linux host create one. The
guest grows the filesystem to `hw.rootfs_mib` on first boot, with the `resize2fs`
that rides the boot volume.

Booting is two-stage, and no host directory takes part in it. libkrun boots the
guest on the **boot volume**: a small read-only ext4 image, identical for every
box, holding nothing but the agent and `resize2fs`. The kernel roots on it
(`root=/dev/vda ro init=/terra-agent`) and runs the agent as PID 1 — no virtiofs
root, and no initramfs alternative either (`CONFIG_BLK_DEV_INITRD` is unset in
libkrunfw's kernel). Being a constant, the image is unpacked once into
`~/.terra/cache/` and shared by every box, like `vmlinux`.

Stage one is the agent on that volume: it mounts the pseudo-filesystems, dials
the host over vsock for its **boot plan**, grows every image to its configured
size (the root and each volume — `resize2fs` is out of reach after this point),
then mounts the box's root at `/dev/vdb` and chroots into it. There is no
re-exec: the process is already mapped, and the old root simply becomes
unreachable, which is what keeps the boot volume out of a running sandbox's `df`.
Stage two drives the guest's own tools (`mount`, `ip`, `chroot`) for the rest of
the setup, bakes `on_create` if the stamp inside the root is stale, then runs the
hooks and the workload. One integrated Rust process owns the whole guest
lifecycle.

Everything host and guest still have to say to each other goes over **one vsock
connection**, opened by the guest as its first act:

- the host answers it with the boot plan — so the sandbox's environment, secrets
  included, reaches the guest through memory and is never written to a file
- the same connection carries the one-byte graceful-stop signal behind
  `terra stop` and `systemctl stop` (a single `write`, which is what makes it
  usable from a signal handler)

The `on_create` bake needs no channel at all: the guest records the script it baked
at `/terra/recipe` **inside its own root filesystem** and compares it against the
plan on the next boot. The host never reads it — which is why seeding no longer
forks a second VM: a bare `terra setup` boots one to bake on demand, and a start
lets the same bake happen on its way to the workload.

A running sandbox therefore has exactly the host filesystem its config asked for
and nothing else: `mount` shows `/dev/vdb` (the bounded root), the volumes, the
pseudo-filesystems, and any shares you configured. A box with no `mounts` and no
project directory touches no host filesystem at all.

The guest kernel is compiled into the binary (statically linked, not
`dlopen`ed). A virtio-net NIC is bridged over a socketpair to an in-process
[`smolvm-network`](https://github.com/cryi/smolvm) gateway, which terminates the
guest's traffic and reopens host sockets under the configured egress policy
(DNS-answer learning for allowed hostnames, plus static IP/CIDR rules). Adding a
real NIC disables libkrun's TSI backend, so the gateway is the only network path
out of the guest.

## Release gate

`cargo test` covers config parsing, egress-policy construction, boot-plan
construction, and e2e CLI behavior (exit codes, stdout/stderr) — but not a real
boot. Before tagging a release, run the boot suite on a host with `/dev/kvm`
(CI runs it on every push):

```sh
make dist
TERRA_BIN=$PWD/dist/terra cargo test -p terra --test boot -- --ignored
```

The suite is an ordinary `#[ignore]`d cargo integration test
([`crates/terra/tests/boot.rs`](crates/terra/tests/boot.rs)); config assets live
in [`crates/terra/tests/assets/`](crates/terra/tests/assets/). It boots real
microVMs and asserts what unit tests can't:

- **egress** — an allowlisted host is reachable, an unallowed one is blocked.
- **ownership** — the workload runs as terri (or uid 0 under `--root`), but the
  filesystem *always* maps to terri: `/work` and volumes are terri-owned and
  writable, files land owned by the launching host user, and `--root` changes only
  the exec uid, never the on-disk ownership.
- **ports + isolation** — one VM publishes a port; a second VM reaches it *only*
  with a `hosts:` record naming the host plus the `allow:` rule opening that
  port, and a third VM with neither is blocked (the always-on egress floor).

## Troubleshooting

- **`failed to find tool "x86_64-linux-musl-gcc"`** — `zig` isn't on `PATH`.
  The musl C toolchain is provided by `zig` via `scripts/zig-musl-*`.
- **link error building `terra`** — the kernel ELF isn't built yet. Use
  `make build` to build `vmlinux` first.
- **kernel build fails** — missing kernel build deps (`flex`, `bison`, `bc`,
  `libelf`/`elfutils`, `openssl` dev headers).
- **the guest can't reach anything** — the default mode is `allowlist` with no
  rules, which is *no network*. The boot banner says which posture is in force;
  add `allow:` rules to the recipe, or set `mode: unrestricted-public`, then
  `terra setup` to re-pin it.
- **a connection is blocked and you don't know why** — run `terra logs`.
  A blocked *name* logs `virtio-net: blocking DNS query by allow-host policy
  name=…`, which is the rule you are missing; a connection to a bare IP logs
  `virtio-net: blocking outbound connection by egress policy` with the
  destination, so add that address or CIDR and retry.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
