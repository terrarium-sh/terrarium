# Using a box

The full story behind `terra`'s grammar, the box's files, `terra.yaml`, and the
logs. The quick tour is in the [README](../README.md); the recipe reference is
[docs/recipe.md](recipe.md).

## The grammar

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
itself needs is in [packaging/README.md](../packaging/README.md).)

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

## Where a box lives

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
        ├── terra.log     # the box's diagnostics: terra's, libkrun's, the gateway's (rotated: terra.<date>.log alongside)
        └── diagnostics.log # only under TERRA_DIAGNOSTICS=1: the guest console and stray host output, fresh per run
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

## The manifest: `terra.yaml`

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

## Commands

One VM runs per box. Every command addresses a box as `[BOX]` — its name —
defaulting to the directory's only box:

| command | does |
|---------|------|
| `terra [BOX] setup` | **the one command that pins a recipe source**: pin it to the box, unpack the filesystem, bake `on_create`. BOX is a box of the directory — from `terra.yaml`, or a recipe path — and defaults to the directory's only box. `--trust-recipe` answers its question in advance, `--rebuild` rebuilds the filesystem. `--dry-run` runs every refusal this setup would raise and stops before it changes anything — nothing pinned, no filesystem built, no hook run — exiting 0 if the setup would go through and non-zero with the refusal if not, so a CI step is `terra <box> setup --dry-run`. It resolves the recipe the way the setup it stands for does, which is why it is a flag here rather than a verb of its own: a separate check would answer about the pinned recipe while `setup` pinned the one `terra.yaml` names. The other two flags decide what a setup *does*, the half a dry run skips, so neither can be written alongside it. Booting is `terra <box>`'s job |
| `terra [BOX]` | **use a box** — boot it, or join its terminal if it is already up. There is no `start` and no `attach`: which one you want is a fact about the box. A boot that runs to the end exits with the workload's own status, as `docker run` does. `-d` boots headless; the escape key (default Ctrl-\) detaches and leaves it running. A box that was never set up is offered one, on a terminal only — BOX may be a recipe path here too (`terra ./ci.yaml`), which offers to pin that file and then boots it. A box whose `on_create` bake is running holds its lock without having a session to join, so this says so and stops rather than waiting on a terminal that is not coming |
| `terra [BOX] exec [--root] -- CMD…` | run one command in a running box, and exit with its status. Runs as the workload's user; `--root` runs it as root **without granting the workload anything** — the command comes from the host over a port nothing inside the guest can reach. A terminal is allocated exactly when this end has one, so `terra dev exec -- sh` is an interactive shell and `terra dev exec -- cat f > out` writes plain bytes with nothing to remember; `-t`/`-T` say so outright, for a script driving something that insists on a PTY or one that wants exactly the bytes a redirect would get. `--agent-timeout SECS` bounds the wait for the box's agent |
| `terra [BOX] put SRC DST` / `terra [BOX] get SRC DST` [`--agent-timeout SECS`] | copy one file in (`put`) or out (`get`) of a running box. The verb says which side is the box's, so neither path needs a marker: the box's side is an absolute guest path, the host's is whatever your shell hands over. `get` into a directory keeps the file's own name. One file at a time — a directory is a mount's job |
| `terra [BOX] stop` [`--wait SECS`] | orderly stop: `pre_stop`, then the VM exits; a box still up after 30 s (or the `--wait` value) has its VM killed. Stopping a stopped box succeeds — it is already what was asked for |
| `terra [BOX] rm` [`--purge`] [`--force`] | throw the box away, keeping its recipe (`--purge` takes that too; `--force` removes a running box — it is asked to stop first, waited on for 30 s or the `--wait` value, and killed if it does not go, since what is being removed is the filesystem it is still writing to). `--wait` only means anything alongside `--force`, so it is refused on its own |
| `terra [BOX] storage <show\|export\|import\|prune>` | the box's images — its guest filesystem and volumes. `show` lists them with what each is sized to and what it actually costs on disk (they are sparse, so the two differ a lot), marking any the recipe no longer names; `export FILE` writes them all to one compressed file and `import FILE` replaces another box's images with them, so a box set up from the same recipe elsewhere gets this one's state; `prune` removes the volume images the recipe dropped, and their data with them. `export` and `import` take the box's lock, so neither runs against a live VM |
| `terra [BOX] show` [`--with-env-values`] | the fully-resolved config a run would use: the pinned recipe once the box exists, whatever the source it was pinned from says now. A recipe named by *path* is read as a file, which is how one is reviewed before there is a box. `env:` values print as a placeholder — this output is made to be redirected or pasted into a bug report — and `--with-env-values` is how you ask for them, which is also how you read back what an `env_file:` merged in. A recipe `terra setup` would refuse still prints, with a warning: reading one is what `show` is for, and `terra <box> setup --dry-run` is what answers that question outright, for the recipe that setup would actually pin |
| `terra ls` (`terra ps`) | created? running? — every box of the directory, with where each one's files are (details are `show`'s). `--all` lists every box on this machine instead, each with the directory it belongs to. `--tsv` prints one tab-separated line per box — state, name, directory, files — the format scripts may rely on |
| `terra [BOX] logs` [`-f`] | the box's diagnostics — terra's, libkrun's and the gateway's. The guest's boot and hooks are not in it; `TERRA_DIAGNOSTICS=1` keeps those in diagnostics.log. The workload's terminal is not here either; that is what attaching shows (see *Logs*) |
 | `terra [BOX] sessions` [`--agent-timeout SECS`] | the clients attached to the box's terminal, one line each: the id `terra [BOX] detach` takes, and the terminal size that client reported (`-` for one that reported none). A session is a multiplexed terminal, so several terminals can sit on one box — and one that stopped reading keeps its stale size in the shared view until it is detached |
 | `terra [BOX] detach ID` / `--all` [`--agent-timeout SECS`] | drop one attached client — or every one of them. The client's connection is closed, so whatever terminal it sat on is restored; the detached client's own run ends as if its detach key had been pressed. A client that is already gone is refused rather than silently re-detached |

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

## Logs

A box has one log, `terra.log`, and it is the box's *diagnostics*: terra's own
messages, libkrun's and the gateway's account of what it refused.
`terra [BOX] logs` [`-f`] shows it.

What is deliberately **not** in it is the workload's terminal. The workload's
terminal is the session's: the guest multiplexes it (see *the guest agent*
below) and it reaches whoever is attached, nobody else. A run boot sends its
console output to `/dev/null` unless `TERRA_DIAGNOSTICS=1` repoints it at
diagnostics.log, a `--foreground` boot keeps it on the terminal the process
was started with, and a bake's console goes to this log - a failed
`on_create` replays it so you can fix the recipe. So the two questions have
two answers — `terra logs` for *why is my box broken*, attaching for
*what is it doing* — and neither arrives interleaved with an escape sequence
from the other, which used to corrupt a live TUI and every later replay of the
log.

When the guest's side of a failure is what you need, boot with
`TERRA_DIAGNOSTICS=1`: the console and every stray host write — panics
included — land in `diagnostics.log`, one fresh, unrotated file per run, next
to `terra.log`. A bake that fails replays the tail of `terra.log` on the way
out, which names the mistake on terra's side; the flag is how the guest's side
is read.

The consequence worth knowing: **a run nobody attaches to leaves no record of
what it printed.** A workload that wants one writes it, to a volume that
outlives the box's filesystem anyway. Terra does not keep it for you: a
terminal is not a log, and a box that runs for a month would make it one.

`--foreground` is the one exception, and for the reason the mode exists. That
VM runs inside the terra process a service manager started, so the console
*is* that process's stdout and no client will ever attach to relay the
workload — there, the guest broadcasts its terminal to the console too (the
plan's `workload_on_console`). A systemd unit gets the workload in its journal
and the diagnostics in `terra logs`, which is the same division by another
name.

**The log rolls.** Once a day the appender starts a new `terra.<date>.log` and
repoints `terra.log` at it; the generations stay on disk, so a box you restart
often shows one file per day it ran rather than every run it ever had. `-f`
follows across the repoint without going quiet or repeating itself.

Everything host-side is collected by one `tracing` subscriber, which is also
what makes the gateway's own account of a refusal visible at all — those events
were written to nobody for as long as terra installed no subscriber. The box
log defaults to `info`; `RUST_LOG` overrides it verbatim. Records below the
chosen level are never built at all — libkrun logs through the same facade, so
its chatty device sites cost nothing unless asked for.

A boot that never gets off the ground is reported by the process that spawned
it: it replays the tail of the log rather than leaving you to go looking. (A
`--foreground` boot has no such parent, and needs none — nothing has moved off
its streams yet when a VM fails to start.)

**The guest agent is the guest init (PID 1).** The kernel starts it directly off
the boot volume; it fetches a boot *plan* from terra over vsock (see *How it
works* in [README.dev.md](../README.dev.md)) and brings the guest up — mounts,
NIC, hooks, privilege drop — then runs the workload on a PTY and multiplexes it
over vsock: every client — the launching terminal and every later `terra [BOX]`
— shares one view (all output broadcast, all input forwarded), so an agent like
*pi* can be observed and steered from several places at once. A client attaching
to a running TUI is repainted with the current screen (via a vt100 screen
model), not a corrupt scrollback replay. On an orderly stop the agent runs
`pre_stop` before the VM exits. The agent ships in the boot volume image
`make build` bakes, not in the host binary.

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
`make verify`) into [`packaging/man/`](../packaging/man/) (`terra.1`, `terra-run.1`,
…), together with the shell completions in
[`packaging/completions/`](../packaging/completions/).

Where a `BOX` argument is accepted, a bare name is a box — a `terra.yaml`
entry, or one already set up; anything starting with `.`, `/` or `~` is a
recipe path, and names the box after its stem. A relative host mount path
inside a recipe is resolved against the directory the *box* belongs to, so the
same box shares the same directories from wherever it is addressed
(`--project` included).
