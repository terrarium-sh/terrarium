# Security model

Without host mounts, the VM is the boundary. A hostile workload is contained
by libkrun's hardware-virtualized microVM; the recipe is how you deliberately
open narrow paths back to the host.

## What a recipe can grant

| feature | what crosses the boundary |
|---|---|
| `mounts` | Host directories presented through libkrun virtiofs. A writable mount gives the guest your own access to that directory; `readonly: true` lets it inspect without changing files. It does not confine the VMM to that directory. |
| `network.ports` | A guest listener published on host loopback only. |
| `allow: ["HOST_LOOPBACK:PORT"]`, or an allowed `hosts:` name resolving there | A connection to the computer running terra. This is the only way to reach the host itself. |
| `terra exec` | One host-initiated command in a running box. `--root` makes that command guest root; it does not grant the workload root. |
| `terra put` / `get` | One host-initiated file transfer. |
| `env:` and `env_file:` | Values supplied to guest processes. `env:` values are part of the pinned recipe; `env_file:` values are merged into the in-memory boot plan and never written to guest disk by Terra. |

No `mounts` means Terra exposes no host filesystem through guest devices.

## Mounts require host confinement

libkrun virtiofs does not confine a guest to the configured directory. A guest
can potentially access other host filesystems or directories that the VMM can
access. Treat a mount as granting the guest the VMM's host filesystem access,
not as a narrow filesystem boundary. See libkrun's
[security model](https://github.com/containers/libkrun#security-model).

Terra does not currently confine its VMM. If a workload needs mounts, run
terra inside a host sandbox that exposes only the shares and VM runtime files:
on Linux, use a mount namespace; on macOS, use an equivalent system sandbox.
Running terra as a dedicated unprivileged user is weaker but useful
confinement: the guest can still reach every file that user can reach, so that
account must have access only to the shares and VM runtime files. Otherwise,
do not use `mounts`.

Terra's mount checks reduce accidental authority, but are not confinement. It
refuses a mount that resolves to `~/.terra`, or a writable mount that resolves
to the terra binary: those files define later boxes and boots, so a guest must
never be able to rewrite them. libkrun opens a share by path after this check,
so do not mount a path whose parent another process, including another running
box, can replace.

A recipe source inside a directory a currently pinned box shares read-write is
treated as possibly guest-authored: `terra setup` shows what it grants and asks
before pinning it. In scripts, `--trust-recipe` is that explicit approval.
Terra does not retain former shares, so treat files that were once shared
read-write as untrusted too.

Host paths used by `put`, `get`, and `env_file` are opened without following
symlinks. A guest cannot turn a shared-directory symlink into access somewhere
else on the host.

## Network

The network policy filters egress. In both modes, the host, LAN, private ranges,
link-local addresses, and cloud metadata remain blocked unless an `allow` rule
explicitly permits them. `unrestricted-public` opens public internet access;
`allowlist` opens only listed destinations.

An allowed service is trusted: encrypted traffic to it can carry any protocol,
including DNS-over-HTTPS. Keep `allow` rules as narrow as the workload permits.
See the [recipe reference](recipe.md) for DNS and rule syntax.

## What is not a boundary

- **Guest root, `sudo:`, and hooks.** These protect the box's own filesystem,
  not the host. Hooks deliberately run as guest root.
- **The recipe.** It can mount host paths and run root hooks. Review it like a
  shell script before setup, especially when it comes from a repository.
- **A configured mount.** libkrun does not make it a host filesystem boundary.
  Contain the VMM outside Terra or run without mounts.
- **Your terminal.** Attached workload output is intentionally raw so TUIs work.
  A hostile workload can emit terminal escape sequences; use a terminal policy
  that disables features you do not trust.
- **Running terra as host root.** Writable mounts then give the guest real root
  ownership on the host. On Linux, run as an unprivileged user in the `kvm`
  group; otherwise use read-only mounts, or set `TERRA_ALLOW_ROOT=1` only when
  you mean it.

## Host state and services

Box state, the shared cache, logs, and guest images live under `~/.terra`.
Terra keeps those directories owner-only and refuses to run if it cannot. The
host-facing guest-agent services for sessions, files, and `exec` accept only
the host's vsock peer. The control listener accepts the guest agent once, then
stops listening; that connection remains open for the orderly-stop signal.

Terra pins libkrun, libkrunfw, and the egress gateway as submodules.
Downloaded build inputs are checksum-verified. See
[vendor/README.md](../vendor/README.md) for the dependency policy.

## Report a vulnerability

Please follow the [security policy](../SECURITY.md) or
[report privately on GitHub](https://github.com/Berry-Studio/terrarium/security/advisories/new).
