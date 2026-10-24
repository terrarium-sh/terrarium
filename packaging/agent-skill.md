---
name: terra-box
description: Turn a user's requirements into a Terrarium box - a terra recipe plus terra.yaml - then check it, set it up and smoke-test it. Use when asked to sandbox, isolate or containerize a project, coding agent, tool or service with terra or Terrarium, or to write, fix or extend a terra recipe.
---

# Build a terra box

A box is a lightweight VM that `terra` builds from a YAML recipe. It starts with
no host files and no network; the recipe grants each. Write the smallest recipe
that meets the requirements, check it with `terra`, then set it up. `terra
--help` describes the installed version; where it disagrees with this guide,
it wins.

## Workflow

1. **Gather requirements.** Read the project first (README, lockfiles,
   Dockerfile, CI config, `.env.example`) and ask the user only what it cannot
   answer. Never grant more access to save a question.

   | Requirement | Recipe field |
   | --- | --- |
   | What runs: a shell, an agent CLI, a server, a one-shot command | `workload`, `daemons` |
   | Tools and packages | `hooks.on_create`, and their registries in `network.allow` |
   | Host folders, and whether the box may write them | `mounts`, `readonly` |
   | State that persists but stays off the host | `volumes` |
   | Hosts, APIs and host services it calls | `network.allow`, `network.hosts` |
   | Services the user opens from the host | `network.ports` |
   | Secrets and API keys | `env_file` |
   | CPU, memory, disk | `hw` |
   | Root for named commands at runtime | `sudo` |

2. **Write the recipe** with the reference below, and a `terra.yaml` naming it
   unless the user wants a single recipe set up by path (`terra ./box.yaml setup`).
3. **Check it:** `terra <box> setup --dry-run` exits non-zero with the reason
   when terra would refuse it. `terra <box> show` prints the resolved recipe.
4. **Set it up:** `terra <box> setup` pins the recipe, builds the disk and runs
   `on_create`, printing its output.
5. **Smoke-test:** `terra <box> -d` starts it in the background; `terra <box>
   exec -- CMD` runs a check inside, such as a version or a test. `-d`
   returns before `on_start` finishes, so retry a check that depends on it.
   `terra <box> logs` lists blocked destinations as `egress: blocked` lines.
   Allow only the ones the workload needs, then `terra <box> stop` and set up
   again.
6. **Hand over:** tell the user what the box can read, write and reach, and how
   to use it: `terra <box>` attaches, `Ctrl-\` detaches, `terra <box> stop`
   stops and `terra <box> rm` deletes it (`--force` while it runs).

## Rules

- The guest is Alpine Linux: BusyBox `sh`, musl, `apk add --no-cache` with
  Alpine package names (`build-base`, `python3`, `py3-pip`, `nodejs`, `npm`,
  `git`, `openssh-client`), which need `dl-cdn.alpinelinux.org:443`. glibc-only
  binaries need the `gcompat` package.
- `on_create` installs system packages and global tools. Project dependencies
  need the mount, so install them with `exec` or in the daemon or workload
  that uses them.
- A server the user opens from the host belongs in `daemons`, restarted when
  it fails, and must listen on `0.0.0.0`, as in
  `cd /work && npm install && exec npm run dev -- --host 0.0.0.0`. Through
  `ports`, a `127.0.0.1` listener is unreachable.
- The workload, daemons and `exec` run as `terri` (UID 1000, home
  `/home/terri`). Root is for hooks, `sudo` entries and `exec --root`.
- Size `hw` for the work. The 512 MiB default root filesystem holds little
  beyond Alpine; toolchains want `rootfs_mib: 4096` and `mem_mib: 2048` or more.
- Mount the narrowest folder, `readonly: true` unless the box must write it.
  Never mount `~`, `~/.ssh`, cloud credentials or unrelated projects.
- A writable mount over the project lets the guest edit the recipe and
  `terra.yaml`. Terra then asks before pinning them; without a terminal it
  needs `--trust-recipe`, which you pass only after reviewing both files. For
  untrusted workloads, keep the recipe outside every writable mount: put it and
  `terra.yaml` in a sibling folder, mount `host: ../app`, and run terra there
  or with `--project DIR`.
- Prefer `allowlist` with `host:443` entries; `*.example.com` does not cover
  `example.com`. Use `unrestricted-public` only when the user accepts open
  egress.
- Secrets go in the file `env_file` names, never in the recipe, which is
  usually committed. Every value the guest receives is readable inside it.
- Without a terminal, start boxes with `-d` and run commands with `exec`;
  attaching needs the user's terminal.

Common registries, to start from; the egress log has the final say:

- npm: `registry.npmjs.org:443`
- PyPI: `pypi.org:443`, `files.pythonhosted.org:443`
- crates.io: `index.crates.io:443`, `static.crates.io:443`
- Go modules: `proxy.golang.org:443`, `sum.golang.org:443`
- GitHub over HTTPS: `github.com:443`, `codeload.github.com:443`, and
  `*.githubusercontent.com:443` for raw files and release downloads

## Example

"Run this repository's Python tests in a box. Dependencies come from PyPI;
nothing else should be reachable."

`py.yaml`:

```yaml
hw:
  mem_mib: 2048
  rootfs_mib: 4096
mounts:
  - host: .
    guest: /work
network:
  allow:
    - dl-cdn.alpinelinux.org:443
    - pypi.org:443
    - files.pythonhosted.org:443
hooks:
  on_create: [apk add --no-cache python3 py3-pip]
workload:
  workdir: /work
```

`terra.yaml`:

```yaml
boxes:
  py: ./py.yaml
```

```sh
terra py setup --dry-run && terra py setup
terra py -d
terra py exec -- sh -c 'python3 -m venv ~/venv && ~/venv/bin/pip install -r requirements.txt pytest && ~/venv/bin/pytest'
terra py logs | grep 'egress: blocked'
```

The mount is writable because tests write caches into `/work`; tell the user
that the box can therefore edit `py.yaml` and `terra.yaml`.

<!-- include docs/recipe.md -->

<!-- include docs/manifest.md -->
