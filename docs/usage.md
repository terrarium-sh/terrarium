# Using Terra

`terra` manages the boxes of the project in the current directory. Put the box
name before the verb: `terra [BOX] [VERB]`. With one box, the name is optional.

```sh
terra dev setup
terra dev
terra dev -- npm test
terra dev exec -- sh
terra dev stop
```

`BOX` is a name from `terra.yaml`, an existing box, or a recipe path such as
`./ci.yaml`, which names the box after the file. See
[the manifest reference](manifest.md) and [the recipe reference](recipe.md).
Every command accepts `--project DIR` to work on another project.

## Primary uses

Terra is built around two uses, but any workload that needs a clear boundary
fits in a box.

### A terrarium for agents

Give a long-lived agent a box of its own. The root filesystem and volumes
survive restarts, so its tools and state stay put.

1. Make the agent the recipe's [workload](recipe.md#processes).
2. Share only the directories it should touch, or none, and hand files over
   with `terra <box> sync`.
3. [Allow](recipe.md#network) only the destinations it needs.

`terra <box> logs` shows network denials as `egress: blocked` lines. To keep
the agent running across host restarts, use the
[systemd unit](../packaging/README.md#running-terra-under-systemd).

### A dev VM for your harness

Run Claude Code, Codex or your own tooling against a project without handing it
your host. [Mount](recipe.md#mounts) the project, mark anything the harness only
reads `readonly`, and allow the registries and APIs it calls. Detach with
`Ctrl-\`, rejoin with `terra dev`, and run one-off commands with
`terra dev exec`. The [quickstart](../README.md#quickstart) builds this setup.

### Let an agent build the box

The [terra-box skill](../skills/terra-box/SKILL.md) teaches Claude Code, Codex
and other agents to turn your requirements into a recipe, check it, set it up
and test it. Install it into your agent's skills folder, for Claude Code:

```sh
mkdir -p ~/.claude/skills/terra-box
curl -fsSL -o ~/.claude/skills/terra-box/SKILL.md https://raw.githubusercontent.com/terrarium-sh/terrarium/main/skills/terra-box/SKILL.md
```

## Installation options

Use the [quickstart installers](../README.md#quickstart) or
[build from source](../README.dev.md). Check the
[platform requirements](../packaging/README.md) first.

The installer verifies the release checksum, and its GitHub attestation when the
GitHub CLI is installed. Run it again to upgrade.

| | Linux and macOS | Windows |
| --- | --- | --- |
| Pin a version | `curl -fsSL …/install.sh \| TERRA_VERSION=x.y.z sh` | `$env:TERRA_VERSION="x.y.z"; irm …/install.ps1 \| iex` |
| Include prereleases | `curl -fsSL …/install.sh \| TERRA_PRERELEASE=1 sh` | `$env:TERRA_PRERELEASE=1; irm …/install.ps1 \| iex` |

On Windows, `terra.exe` goes to `%LOCALAPPDATA%\Programs\terra`, which the
installer adds to your `PATH`; open a new terminal afterwards.

To verify a downloaded archive yourself:

```sh
gh attestation verify terra-x86_64-linux.tar.gz --repo terrarium-sh/terrarium
```

## Set up and start

`terra <box> setup` reads the recipe, asks for approval when needed, pins it,
creates storage and runs `on_create`. Run it again after changing the recipe.
`--dry-run` checks the recipe without changing anything. Without a terminal, a
recipe a guest might have written needs `--trust-recipe` after you review it.

`terra <box>` starts the box, or attaches if it is already running. It runs the
recipe's workload, or the command after `--` for that boot only.

- `--root` runs that boot's workload and daemons as guest root.
- `-d` starts the box in the background.
- `--foreground` is for a service manager: the VM stops when the command exits.

Without a terminal, a start needs `-d` or `--foreground`.

The workload has one shared session. Press `Ctrl-\` to detach without stopping
it and `terra <box>` to rejoin. `terra <box> sessions` lists attached clients;
`terra <box> detach ID` or `--all` disconnects them.

## Work with a running box

```sh
terra dev exec -- make test
terra dev exec --root -- apk add strace
terra dev sync ./src/ :/app/
terra dev sync :/app/output/ ./output/
terra dev logs -f
```

- `exec` runs a command beside the workload; `--root` applies to that command
  only.
- `logs` shows Terra's host diagnostics, and `--diagnostics` the guest's. Both
  are replayed after a failed boot. Workload output goes to the session.
- `show` prints the pinned recipe. Environment values stay hidden unless you
  pass `--with-env-values`.

### Sync files

`sync` copies one way between the host and a running box. `box:/path` and
`:/path` both mean a path in the selected box.

- A source folder ending in `/` copies its contents; without `/`, it lands as a
  subfolder of the destination.
- Files with the same size and modification time are skipped. `--checksum`
  compares SHA-256 contents instead.
- `--delete` removes destination files the source lacks, inside the destination
  folder only.
- `--dry-run` shows what would change without changing it.

Sync keeps modification times and permission bits. Windows hosts keep only the
read-only attribute, so their files arrive as `0755`, or `0555` when read-only.
Symlinks are copied as links, never followed, and downloaded links must point
inside the synced tree. A source that is itself a symlink is copied as a link;
give its target path to sync the folder. Special files and non-UTF-8 names are refused.

Sync is not a transaction: a failed file keeps its old copy, but files already
synced stay changed. Keep the source and the host destination still while a
sync runs, including through a writable share. Sync refuses:

- names that would collide on the destination, such as two spellings that a
  case-insensitive filesystem treats as one.
- a folder replacing a file or the reverse, even with `--delete`. Remove the
  destination entry first.
- metadata-only updates to a file with several hard links. Replace it with an
  independent copy first.
- on Windows, device names, invalid characters, trailing dots or spaces, and
  names or link targets containing `~`.

Downloads need a writable destination folder, even for `--dry-run`, because
Terra briefly creates and removes test names there to detect collisions.

## Network access

`network.allow` grants external destinations and `network.ports` publishes
guest services on host loopback. Guest localhost and guest-local routes stay
inside the guest. `network.enabled: false` turns off external networking while
Terra commands keep working. See [the recipe reference](recipe.md#network) and
[the security model](security.md#network).

## List boxes

`terra ls` (or `terra ps`) lists the project's boxes; `--all` lists every
project's.

```sh
terra ls --state running --quiet
terra ls --state stopped,not_created
terra ls --all --state running --json
```

- States are `running`, `setting_up`, `stopped`, `not_created` and `gone`.
  Repeat `--state` or join states with commas to match any of them.
- Filters work with every format, including `--json` and `--tsv`. No match
  prints nothing, or `[]` for JSON.
- `-q` (`--quiet`) prints one name per line and cannot be combined with JSON or
  TSV. With `--all`, names can repeat across projects; use JSON or TSV to see
  each project's path.

## Upgrade

Each boot uses the guest kernel and agent bundled with the `terra` that starts
the box. After upgrading Terra, stop and start each running box to move it to
the new release; `sync` needs this when the agent protocol changed. Existing
boxes do not need rebuilding, and attaching to a running box changes nothing.
Guest package updates never change the kernel.

## Stop, storage and removal

- `terra <box> stop` shuts the box down in order, running `pre_stop`.
- `terra <box> rm` removes the box's storage, logs and sockets but keeps its
  pinned recipe; `--purge` removes that too. `--force` removes a running box
  after trying a graceful stop.
- `terra <box> storage show` lists the root filesystem and volumes. `export`
  writes the images to a file and `import` loads one back, into a stopped box
  with the same recipe. `prune` deletes images the recipe no longer names.

Box state lives under `~/.terra/box/t-<project-slug>/<box>/`; the slug is a
stable hash of the project path.

Disk images are sparse: deleting files in the box gives the space back to the
host, while the guest keeps its full configured capacity. This needs a host
filesystem that supports sparse files.

Read the [security model](security.md) before using mounts, public network
access, or files from a guest on the host.
