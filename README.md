# Terrarium

A KISS microsandbox for AI agents — one static binary, a YAML recipe, and your
project directory. Built on [libkrun](https://github.com/libkrun/libkrun).

[![CI](https://github.com/alis-is/terrarium/actions/workflows/build.yml/badge.svg)](https://github.com/alis-is/terrarium/actions)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Terrarium runs a workload in a real KVM microVM with exactly the host files it
was granted and exactly the network it was allowed. No daemon, no images to
pull, nothing fetched at run time — the guest root filesystem is baked into the
binary.

## Quickstart

```sh
curl -fsSLO https://raw.githubusercontent.com/alis-is/terrarium/main/install.sh
sh install.sh
```

The script verifies the release checksum before it puts anything in place, and
installs the latest release: `/usr/local/bin/terra` on Linux,
`/opt/homebrew/bin` (or `/usr/local/bin`) on macOS. Pin one with
`TERRA_VERSION=x.y.z sh install.sh`. Prefer building from source?
[README.dev.md](README.dev.md).

Then sandbox a project:

```sh
cd ~/code/my-app
cat > dev.yaml <<'EOF'
hw: { cpus: 2, mem_mib: 1024 }
mounts:
  - { host: ".", guest: /work }          # your project, visible at /work
network:
  mode: unrestricted-public              # or allowlist + explicit rules
workload:
  entrypoint: /bin/sh                    # a shell instead of your app's cmd
EOF
terra ./dev.yaml setup      # pin the recipe, build the box (runs on_create)
terra                       # boot it — a shell, cwd at /work
```

`terra` boots the box, or joins its terminal if it is already up. Detach with
`Ctrl-\`, stop with `terra stop`, delete with `terra rm`.

Want the included recipe instead?
`cp pi-dev.yaml ~/.terra/ && terra setup pi-dev && terra pi-dev`.

## A recipe is a policy

Every key is optional. An empty recipe boots a shell with no host filesystem
and no network at all — nothing is shared or reachable unless it is written
down:

```yaml
hw: { cpus: 2, mem_mib: 1024, rootfs_mib: 4096 }
mounts:                       # host dirs the guest can see — none by default
  - { host: ".", guest: /work }
  - { host: ~/.ssh, guest: /home/terri/.ssh, readonly: true }
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

- **Real isolation.** Each box is a KVM microVM, not a container.
- **Deny-by-default network.** An egress allowlist (default) or public-only
  egress; the host, its LAN and every private range are always blocked unless a
  rule names them.
- **One static binary.** No daemon, no runtime dependencies, no downloads.
- **Hooks.** `on_create` (once), `on_start` (every boot), `pre_stop` (on
  orderly shutdown) — all run as guest root.
- **Detach and rejoin.** `Ctrl-\` hands the terminal back and the box keeps
  running; `terra` re-attaches, and several watchers share one session.
- **Files in and out.** `terra put` / `terra get` copy files across the
  boundary; `terra exec --root -- CMD` runs one command inside a live box.
- **Bounded state.** Volumes and rootfs are fixed-size, capped images; `terra
  rm` resets the box to its recipe.

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

## Security

The boundary is the VM. A box has the host filesystem its recipe lists and the
network its recipe allows — nothing else. Box state lives outside your project
in `~/.terra/box/`, so sharing `host: .` never hands the guest the rules of its
own next boot. What crosses the boundary, what cannot, and what is deliberately
not a boundary: [docs/security.md](docs/security.md).

## Documentation

- [docs/usage.md](docs/usage.md) — how a box works: the CLI, `terra.yaml`, logs
- [docs/recipe.md](docs/recipe.md) — every recipe key, in detail
- [docs/security.md](docs/security.md) — the security model and its limits
- [README.dev.md](README.dev.md) — building from source, how it works,
  porting, releasing
- [packaging/README.md](packaging/README.md) — systemd units, man pages

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
