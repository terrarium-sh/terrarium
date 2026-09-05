# Terrarium

Run coding agents and development tools in a hardware-virtualized microVM with
only the host files and network access you grant it.

Terrarium is a minimal sandbox: one self-contained `terra` binary, a YAML
recipe, and your project directory. It uses
[libkrun](https://github.com/libkrun/libkrun) for the microVM and
[smolvm](https://github.com/smol-machines/smolvm) for controlled networking.

[![CI](https://github.com/Berry-Studio/terrarium/actions/workflows/build.yml/badge.svg)](https://github.com/Berry-Studio/terrarium/actions)
[![Latest release](https://img.shields.io/github/v/release/Berry-Studio/terrarium)](https://github.com/Berry-Studio/terrarium/releases/latest)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Terrarium runs a workload in a microVM with exactly the host files it was
granted and exactly the network it was allowed to reach. No daemon; no images to
pull or runtime downloads — the guest root filesystem is baked into the binary.

Release binaries are available for x86_64 and aarch64 Linux, plus Apple Silicon
macOS. Linux requires read-write access to `/dev/kvm`. Windows is not supported
yet; see [Windows support](docs/windows-port.md) for the plan. Terrarium may
work in WSL2 when its distribution has read-write access to `/dev/kvm`.

## Quickstart

```sh
curl -fsSLO https://raw.githubusercontent.com/Berry-Studio/terrarium/main/install.sh
sh install.sh
terra --version
```

The script checks the downloaded binary against the release's published
checksum before it puts anything in place, and installs the latest release:
`/usr/local/bin/terra` on Linux,
`/opt/homebrew/bin` (or `/usr/local/bin`) on macOS. Pin one with
`TERRA_VERSION=x.y.z sh install.sh`; re-run `sh install.sh` to upgrade. To pin
both the installer and binary,
download `install.sh` from that release tag instead of `main`:

```sh
version=vX.Y.Z
curl -fsSLO "https://raw.githubusercontent.com/Berry-Studio/terrarium/$version/install.sh"
TERRA_VERSION="$version" sh install.sh
```

Prefer building from source?
[README.dev.md](README.dev.md).

New release binaries carry a signed build-provenance attestation. With the
GitHub CLI, verify the installed binary with:

```sh
gh attestation verify "$(command -v terra)" --repo Berry-Studio/terrarium
```

Then sandbox a project:

```sh
cd ~/code/my-app
cat > dev.yaml <<'EOF'
hw: { cpus: 2, mem_mib: 1024 }
mounts:
  - { host: ".", guest: /work }          # writable project mount; use readonly to inspect only
network:
  mode: unrestricted-public              # public egress; host and private networks stay blocked
workload:
  entrypoint: /bin/sh                    # a shell instead of your app's cmd
  workdir: /work                         # so the shell starts at your project
EOF
cat > terra.yaml <<'EOF'
boxes:
  dev: ./dev.yaml
EOF
terra ls                    # the manifest declares dev, initially not-created
terra dev setup             # pin dev's recipe, build the box (runs on_create)
terra ls                    # dev is stopped and ready to boot
terra dev                   # boot dev — a shell, cwd at /work
```

The example opts in to public egress for package managers and agents. Remove
the `network:` block for no network, or use `mode: allowlist` with explicit
rules for a narrower policy.

![Terminal demo: create a box from dev.yaml, then enter it.](docs/demo.gif)

`terra` boots the default box, or joins its terminal if it is already up. Detach with
`Ctrl-\`, stop with `terra stop`, delete with `terra rm`.

Want the included recipe instead?
`cp pi-dev.yaml ~/.terra/ && terra ~/.terra/pi-dev.yaml setup && terra pi-dev`.

## A recipe is a policy

Every key is optional. An empty recipe boots a shell with no host filesystem
and no network at all — nothing is shared or reachable unless it is written
down:

```yaml
hw: { cpus: 2, mem_mib: 1024, rootfs_mib: 4096 }
mounts:                       # host dirs the guest can see — none by default
  - { host: ".", guest: /work }
volumes:                      # bounded, persistent scratch disks
  - { name: data, guest: /data, size_mib: 1024 }
network:
  mode: allowlist             # the default: nothing is reachable…
  allow:                      # …unless a rule names it
    - api.openai.com:443
hooks:
  on_create:                  # once, baked into the box's rootfs
    - apk add --no-cache git
workload:
  entrypoint: /bin/sh
```

`terra setup` is the only command that pins a recipe — every boot runs the copy
pinned inside the box, so editing a recipe changes nothing until you re-run it.
Every key: [docs/recipe.md](docs/recipe.md).

## What you get

- **Real isolation.** Each box is a microVM, not a container.
- **Deny-by-default network.** An egress allowlist (default) or public-only
  egress; the host, its LAN and every private range are always blocked unless a
  rule names them.
- **One binary.** No daemon, images to pull, or runtime downloads.
- **Hooks.** `on_create` (once), `on_start` (every boot), `pre_stop` (on
  orderly shutdown) — all run as guest root.
- **Detach and rejoin.** `Ctrl-\` hands the terminal back and the box keeps
  running; `terra` re-attaches, and several watchers share one session.
- **Files in and out.** `terra put` / `terra get` copy files across the
  boundary; `terra exec --root -- CMD` runs one command inside a live box.
- **Bounded state.** Volumes and rootfs are fixed-size, capped images; `terra
  rm` removes them but retains the pinned recipe unless given `--purge`.

## Commands

| command | what it does |
|---|---|
| `terra [BOX] setup` | pin the recipe, build the box |
| `terra [BOX]` | boot it — or join it if it's up (`-d`: headless) |
| `terra [BOX] -- CMD…` | run CMD instead of the recipe's workload, for one boot |
| `terra [BOX] exec [--root] -- CMD…` | one command inside a running box |
| `terra [BOX] put/get SRC DST` | copy one file in / out |
| `terra [BOX] logs [-f]` | the box's diagnostics |
| `terra [BOX] sessions` | the clients attached to the box's terminal |
| `terra [BOX] detach ID` / `--all` | drop one attached client — or every one |
| `terra [BOX] stop` / `rm` | graceful stop (runs `pre_stop`) / delete |
| `terra ls` | every box: created? running? where? |

`[BOX]` defaults to the directory's only box. Full command reference:
[docs/usage.md](docs/usage.md).

## Storage

Boxes live outside the project at `~/.terra/box/<project>/<box>/`; each holds
its pinned recipe, root filesystem, volumes, and logs. `~/.terra/cache/` holds
the shared guest kernel and boot image.

Use `terra ls --all` to find boxes across projects, then
`terra <box> rm --purge --project <project-dir>` to remove a box and all of its
state. The locations are fixed. To put Terra's state on another disk, stop all
boxes, move `~/.terra`, and make `~/.terra` a symlink to the new location. The
target must honour owner-only permissions; it is security-sensitive state.
Details: [docs/usage.md](docs/usage.md#where-a-box-lives).

## Security

The boundary is the VM. A box has the host filesystem its recipe lists and the
network its recipe allows — nothing else. Box state lives outside your project
in `~/.terra/box/`, so sharing `host: .` never hands the guest the rules of its
own next boot. What crosses the boundary, what cannot, and what is deliberately
not a boundary: [docs/security.md](docs/security.md).

To report a vulnerability privately,
[open a GitHub security advisory](https://github.com/Berry-Studio/terrarium/security/advisories/new).

## Documentation

- [docs/usage.md](docs/usage.md) — how a box works: the CLI, `terra.yaml`, logs
- [docs/recipe.md](docs/recipe.md) — every recipe key, in detail
- [docs/security.md](docs/security.md) — the security model and its limits
- [README.dev.md](README.dev.md) — building from source, how it works,
  porting, releasing
- [packaging/README.md](packaging/README.md) — systemd units, man pages
- [SECURITY.md](SECURITY.md) — reporting security vulnerabilities

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
