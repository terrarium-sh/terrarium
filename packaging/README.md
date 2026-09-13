# Running terra under systemd

`terra <box> --foreground` runs the microVM in its own process and exits when the
VM stops — so it maps cleanly onto a `Type=exec` service, the same shape podman
uses. The templated unit [`terra@.service`](terra@.service) is two steps, because
only `setup` reads a recipe *path* and a boot takes a box *name*:

```
systemctl start terra@pi-dev
  # -> terra /var/lib/terra/.terra/pi-dev.yaml setup --trust-recipe
  #    terra pi-dev --foreground
```

The instance name is the recipe file's stem, so the box is named `%i` too. Setup
runs on every start, which is what makes editing the recipe and restarting the
service mean something; on an unchanged recipe it pins nothing and re-bakes
nothing.

A box lives at `~/.terra/box/<slug of its project directory>/<name>`, so what the
unit's `WorkingDirectory` decides is the slug — which is why it carries `%i`. Do
not drop it: with a shared working directory both instances resolve to the *same*
box, and because setup only builds a guest filesystem when none exists, starting
the second recipe would rewrite that box's recipe and then boot the filesystem
the first one's workload had been writing to.

## What terra needs from the environment

These are the requirements the unit satisfies; anything stricter breaks it.

| Requirement | Why | Unit knob |
|---|---|---|
| `/dev/kvm` read-write | the native VMM runs on KVM | `SupplementaryGroups=kvm`, `DeviceAllow=/dev/kvm rw`, no `PrivateDevices` |
| Executable mappings | loading embedded AOT components | `MemoryDenyWriteExecute=no` |
| Real host network | WASI capability imports open authorized host sockets | no `PrivateNetwork`, no `IPAddressDeny` |
| Writable `$HOME/.terra` | cache of the guest kernel and boot volume (unpacked once, shared by every box), plus the box state | `StateDirectory=terra` + `Environment=HOME=%S/terra` |
| A recipe to boot | `~/.terra/%i.yaml`, read by the `ExecStartPre` setup | yours to install; see below |

The runtime needs no host namespace privileges. Host-directory mounts use the
paths granted by the recipe. Run the service as the unprivileged `terra` user with KVM
access; host-root execution is refused unless `TERRA_ALLOW_ROOT=1` is set.

## One-time host setup

```sh
# Install the binary and the unit.
install -m0755 dist/terra /usr/local/bin/terra
install -m0644 packaging/terra@.service /etc/systemd/system/

# Man pages (generated from the CLI at build time).
install -m0644 dist/man/*.1 /usr/local/share/man/man1/

# Dedicated account in the kvm group (state lives in /var/lib/terra via StateDirectory).
useradd --system --home-dir /var/lib/terra --shell /usr/sbin/nologin --groups kvm terra

# The recipe the instance boots. ~/.terra is terra's own directory, which no box
# can share — which is what lets the unit pass --trust-recipe honestly.
install -d -o terra -g terra -m0700 /var/lib/terra/.terra
install -o terra -g terra -m0600 pi-dev.yaml /var/lib/terra/.terra/

systemctl daemon-reload
systemctl enable --now terra@pi-dev
journalctl -u terra@pi-dev -f
```

The recipe should define a `workload:` — headless there's no interactive shell to
fall back to. Use recipe mounts for shared directories, and `terra put`,
`terra get`, or volumes for guest files.

## Graceful stop

`systemctl stop` (SIGTERM) shuts the guest down orderly: terra writes one byte on
the guest's control connection, the agent stops the workload (SIGTERM, then
SIGKILL if it is still there 30 seconds later — an interactive shell ignores
SIGTERM) and runs the recipe's `pre_stop` hooks, then the VM exits. The unit's
`TimeoutStopSec` is 65 seconds; after that systemd
escalates to SIGKILL, which still leaves no orphan (the VM runs inside terra's
process).

## Where the output goes

The journal receives the attached workload's terminal output.
`terra logs pi-dev --diagnostics` shows Terra and guest lifecycle diagnostics,
including hook output and network denials. Kernel console collection is not implemented by
the component backend.

The foreground CLI owns and waits for the VM worker. systemd keeps both in the
service cgroup; orderly stop is forwarded to the worker. To send input, attach
from another terminal with `terra pi-dev`; `Ctrl-\` detaches that client.

## Native host builds

Each executable embeds Linux guest assets for its guest architecture and AOT
components compiled for its host target. A serialized Wasmtime component is not
portable between hosts. Build the guest assets on Linux, then build the host
executable with the matching `build/` directory:

| Host target | Guest assets | Host build |
| --- | --- | --- |
| `aarch64-apple-darwin` | `make ARCH=aarch64 guest-assets` | `make TERRA_TARGET=aarch64-apple-darwin host-dist` |
| `x86_64-pc-windows-msvc` | `make ARCH=x86_64 guest-assets` | `pwsh ./scripts/build-host.ps1 -Target x86_64-pc-windows-msvc` |
| `aarch64-pc-windows-msvc` | `make ARCH=aarch64 guest-assets` | `pwsh ./scripts/build-host.ps1 -Target aarch64-pc-windows-msvc` |

macOS requires Apple Silicon and macOS 15 or newer. The release executable must
be signed with `packaging/macos.entitlements`, which grants
`com.apple.security.hypervisor`. CI uses an ad-hoc signature to check the
entitlement; a distributed macOS executable needs the project's release signing
identity.

Windows x64 requires Windows 10 version 1809 or newer with Windows Hypervisor
Platform enabled. Windows ARM64 requires Windows 11 24H2 build 26100.3915 or
newer with the same feature. Terra checks the hypervisor capability before it
creates a partition, and checks ARM64 support on ARM hosts. The Windows CI jobs
run shared/VMM unit tests and exercise the CLI; they do not establish VM boot
coverage.

`make dist` includes `LICENSE`, `NOTICE`, GPL-2.0, and the selected MIT license texts
beside the executable. Windows builds select windows-sys under Apache-2.0; its
license and Microsoft attribution are in the root `LICENSE` and `NOTICE`.
