# 🪴 Terrarium

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

The installer checks the release checksum before installing. Pin a release with
`TERRA_VERSION=x.y.z sh install.sh`; re-run it to upgrade. Build from source:
[README.dev.md](README.dev.md). Verify a release binary with
`gh attestation verify "$(command -v terra)" --repo Berry-Studio/terrarium`.

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
terra ./dev.yaml setup      # pin the recipe, build the box
terra                       # boot it — a shell, cwd at /work
```

The example opts in to public egress for package managers and agents. Remove
`network:` for no network, or use `mode: allowlist` for a narrower policy.

![Terminal demo: create a box from dev.yaml, then enter it.](docs/demo.gif)

`terra` boots the only box in the directory, or joins it if already up. Detach
with `Ctrl-\`, rejoin with `terra`, stop with `terra stop`, delete with `terra rm`.
Detailed instructions: [docs/usage.md](docs/usage.md).

## What you get

- **Real isolation.** Each box is a microVM, not a container.
- **Explicit access.** No host files or network by default; the host, LAN, and
  private ranges stay blocked unless a recipe names them.
- **One binary.** No daemon, images to pull, or runtime downloads.
- **Lifecycle hooks.** `on_create`, `on_start`, and `pre_stop` run as guest
  root.
- **Work without rebuilding.** Detach, rejoin, copy files, or run `terra exec`
  in a live box.

## Commands

| command | what it does |
|---|---|
| `terra [BOX] setup` | pin the recipe, build the box |
| `terra [BOX]` | boot it — or join it if it's up (`-d`: headless) |
| `terra [BOX] -- CMD…` | run CMD instead of the recipe's workload, for one boot |
| `terra [BOX] exec/put/get` | run a command or copy one file |
| `terra [BOX] logs/sessions/detach` | inspect or manage a live box |
| `terra [BOX] stop/rm` | stop it gracefully / delete it |
| `terra ls` | list boxes in this directory (`--all`: every project) |

`[BOX]` defaults to the directory's only box. Full reference:
[docs/usage.md](docs/usage.md).

## Storage

Boxes live at `~/.terra/box/<project>/<box>/`; shared boot files live in
`~/.terra/cache/`. `terra ls --all` finds them, and
`terra <box> rm --purge --project <project-dir>` removes one completely. To use
another disk, stop boxes, move `~/.terra`, then symlink it back; the target must
honour owner-only permissions.

## Security

The VM is the boundary: a box gets only the mounts and egress its recipe grants.
Read the [security model](docs/security.md), or
[report a vulnerability privately](https://github.com/Berry-Studio/terrarium/security/advisories/new).

## Documentation

- [Recipe reference](docs/recipe.md)
- [Project manifest (`terra.yaml`)](docs/manifest.md)
- [Usage and storage](docs/usage.md)
- [Development and release](README.dev.md)
- [Systemd and man pages](packaging/README.md)
- [Security policy](SECURITY.md)

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
