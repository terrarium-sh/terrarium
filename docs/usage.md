# Using Terra

`terra` manages a box in the current project. Its command shape is
`terra [BOX] [VERB]`: put the box name before the verb. When the project has
one box, the name is optional.

```sh
terra dev setup
terra dev
terra dev -- npm test
terra dev exec -- sh
terra dev stop
```

`BOX` is a name from `terra.yaml`, an existing box, or a recipe path such as
`./ci.yaml`; a recipe path names the box from its filename. See
[the manifest reference](manifest.md) and [the recipe reference](recipe.md).

## Set up and start

`terra <box> setup` reads the recipe, asks for approval when required, pins it,
creates storage, and runs `on_create`. Re-run it after changing the recipe.
Use `--dry-run` in automation to validate setup without changes. A
noninteractive setup of a recipe that a guest might have written requires
`--trust-recipe` after review.

`terra <box>` starts a stopped box or attaches to an already-running box. It
starts the recipe's workload unless `-- CMD…` supplies one command for that
boot. `--root` runs that boot's workload and daemons as guest root. Use `-d` to start
headless; `--foreground` is for a service manager that owns the VM process.
A noninteractive start needs `-d` or `--foreground`.

The workload has one shared session. Press `Ctrl-\` to detach without stopping
it, then run `terra <box>` to join again. `terra <box> sessions` lists attached
clients, and `terra <box> detach ID` or `--all` removes them.

## Kernel updates

Each boot uses the guest kernel bundled with the `terra` binary that starts
the box. After upgrading Terra, run `terra <box> stop`, then `terra <box>` to
use that release's kernel. Existing boxes do not need rebuilding. Attaching
to a running box leaves its kernel unchanged.

The kernel and read-only boot disk are decompressed directly into memory on
each boot, without disk files or a cache. Using the latest Terra release gives you the kernel shipped with that
release; guest package updates do not change the kernel Terra boots.

## Work with a running box

```sh
terra dev exec -- make test
terra dev exec --root -- apk add strace
terra dev put ./input.txt /tmp/input.txt
terra dev get /tmp/result.txt ./result.txt
terra dev logs -f
```

`exec`, `put`, and `get` require a running box. `exec` runs separately from the
workload; use `--root` only for that command. `put` copies one host file into
the guest and `get` copies one guest file out. `logs` contains Terra diagnostics;
attach to the box for workload output. Guest VM diagnostics are written to
`diagnostics.log`, replayed after a failed boot, and available through
`terra <box> logs --diagnostics`.

`terra <box> show` prints the effective pinned recipe for review. Environment
values stay redacted unless `--with-env-values` is passed.

## Stop, storage, and removal

`terra <box> stop` requests an orderly shutdown, including `pre_stop`.
`terra <box> rm` removes guest storage, logs, and sockets but keeps the pinned
recipe. Add `--purge` to remove the recipe too. `--force` can remove a running
box after attempting a graceful stop.

Box state lives under `~/.terra/box/t-<project-slug>/<box>/`, where the slug is
a stable base32 hash of the project path. The memory-backed boot disk contains
the guest agent and resize helper bundled with the Terra binary. `terra ls` lists boxes in the current project, and
`terra ls --all` lists every local project. `terra <box> storage show` inspects
the root filesystem and volumes; `export`, `import`, and `prune` manage images.
Export and import require a stopped box and the same recipe.

The root filesystem and volumes use discard/TRIM to return freed guest blocks
to the host automatically. Their configured capacity stays the same; physical
space is reclaimed where the host filesystem supports sparse holes, at its
allocation granularity. Deletions made before discard was enabled need a guest
`fstrim` to reclaim their space.

Every command accepts `--project DIR` to operate on another project. Read the
[security model](security.md) before using mounts, public network access, or
guest-provided files on the host.
