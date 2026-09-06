# Using a box

This is the operational guide to `terra`. Define a box in the
[recipe reference](recipe.md); name shared project boxes in
[manifest.md](manifest.md).

## The model

Every command has the same shape: `terra [BOX] [VERB]`. A box belongs to the
current directory, and `[BOX]` is optional when that directory has only one.

```sh
$ cd ~/code/app
$ terra dev setup             # pin dev's recipe and build its box
$ terra dev                   # boot it, or join it if it is already up
$ terra dev -- npm test       # run a one-off command instead of its workload
$ terra dev stop
```

`BOX` is a name from `terra.yaml`, an existing box, or a recipe path such as
`./ci.yaml`; a path names the box after its filename. A project with several
boxes requires a name rather than guessing.

`terra <box> setup` is the explicit way to pin a recipe. Edit a recipe, then
re-run it; every other command uses the copy already pinned in the box. On an
interactive terminal, an unbuilt `terra <box>` shows the recipe and offers the
same setup. A script must make that decision explicitly with `setup` (and
`--trust-recipe` when appropriate).

## Sessions

A box has one multiplexed workload console. `terra <box>` opens it at boot or
joins it later; all attached terminals see the same output and can send input.
Press `Ctrl-\` to detach without stopping the box, then rejoin with
`terra <box>`.

```sh
terra dev -d                  # boot headless
terra dev sessions            # see attached clients
terra dev detach --all        # disconnect clients, leave the box running
terra dev exec -- sh          # a separate shell in a running box
```

## Commands

| command | what it does |
|---|---|
| `terra [BOX] setup` | Pin the recipe and build the box. `--rebuild` discards its filesystem; `--dry-run` checks setup without changing it. |
| `terra [BOX]` | Boot the box or join its console. `-d` starts it headless; `-- CMD…` replaces the workload for one boot. |
| `terra [BOX] exec [--root] -- CMD…` | Run one command in a running box. A terminal is allocated when the caller has one; `-t` and `-T` override that. |
| `terra [BOX] put SRC DST` / `get SRC DST` | Copy one file into or out of a running box. |
| `terra [BOX] logs [-f]` | Show Terra, libkrun, and gateway diagnostics. |
| `terra [BOX] sessions` / `detach` | List console clients or disconnect one (or `--all`). |
| `terra [BOX] stop` / `rm` | Stop gracefully, or remove the box. `rm --purge` removes its pinned recipe too. |
| `terra [BOX] show` | Show the effective recipe; values from `env:` remain redacted unless explicitly requested. |
| `terra [BOX] storage show/export/import/prune` | Inspect, move, or remove the box's rootfs and volume images. |
| `terra ls` | List this directory's boxes; `--all` lists every project. |

Every command accepts `--project DIR` to operate on another project. A
non-interactive bare start without `-d` or `--foreground` exits 125, so
scripts never accidentally wait on a terminal.

## Logs and debugging

`terra logs` is diagnostics, not workload output. The workload console belongs
to the session: attach with `terra <box>` to watch it. A headless workload that
nobody attaches to leaves no console transcript.

Set `TERRA_DIAGNOSTICS=1` when the guest's boot or hook output is needed; it
writes a fresh `diagnostics.log` beside the box's regular `terra.log`.
`--foreground` is for service managers such as systemd: it keeps the VM in the
current process and sends workload output to that process's console.

## Storage and cleanup

Terra keeps box state outside the project at
`~/.terra/box/<project>/<box>/`; shared boot files live in `~/.terra/cache/`.
Your project remains ordinary host files. A mount of `host: .` gives the guest
host filesystem access through the VMM and is safe only when that VMM is
separately host-confined; see the [security model](security.md).

```sh
terra ls --all
terra dev rm
terra dev rm --purge
terra old rm --purge --project ~/code/old-project
```

`rm` removes the guest filesystem and volumes but retains the pinned recipe;
the next `terra <box>` rebuilds it. Use `--purge` to remove everything.
`storage export` and `storage import` move guest state between boxes already
set up from the same recipe. To use another disk, stop boxes, move
`~/.terra`, then symlink it back; the target must preserve owner-only
permissions.

## More detail

- [Recipe reference](recipe.md)
- [Project manifest](manifest.md)
- [Security model](security.md)
- Generated command reference: `make man` writes man pages and completions to
  [packaging/](../packaging/)
