# Terrarium — development

Building and hacking on terra itself. Users start at the [README](README.md).

## Prerequisites

- **libkrun, libkrunfw and smolvm are vendored submodules** — libkrun as
  [`cryi/libkrun`](https://github.com/cryi/libkrun) (a mirror of upstream, so
  host-portability patches have somewhere to live and to be sent upstream from;
  it currently carries none), libkrunfw pristine, built from source for its
  guest kernel, and [`cryi/smolvm`](https://github.com/cryi/smolvm) for its
  `smolvm-network` crate, the egress gateway. All folded into a single
  fully-static `terra` binary. After cloning:
  ```sh
  git submodule update --init   # not --recursive: see vendor/README.md
  ```
- **`zig`** on the build host — it provides the musl C cross-toolchain
  (`scripts/zig-musl-*`), so no musl gcc need be installed.
- **KVM** (`/dev/kvm`) on Linux.

At **run** time terra needs nothing else — no network, no `curl`/`tar`, no
e2fsprogs. The guest root filesystem is prebaked into the binary at build time,
so creating a box is a decompress plus a `set_len`; the filesystem work that
needs Linux (growing the image to `hw.rootfs_mib`) happens inside the guest, which
is always Alpine. That is also what lets a non-Linux host create a box.

The **build** host additionally needs `curl` + `tar` + `unshare` (to fetch and
bake the base rootfs) and downloads a pinned, hash-verified e2fsprogs release to
build the static `mke2fs`/`resize2fs` that get baked in.

## Build

```sh
make build     # vmlinux + prebaked rootfs/boot images + static terra binary
make verify    # cargo fmt --check + clippy -D warnings + full test suite
make dist      # -> dist/terra, one fully-static portable binary
make cross     # cross-compile the host binary (see Platform support)
make clean
```

`terra` is a static-musl PIE binary — `ldd` reports *not a dynamic executable*.
Always use `make dist` to build it; the binary is gitignored.
It links **nothing** at runtime (no libc, no loader, no `.so`) and runs on any
Linux with KVM. libkrun is a mainline Cargo dependency (unmodified); the guest
kernel is libkrunfw's `vmlinux`, embedded and booted as an external kernel —
no dlopen, no patch. It ships stripped and gzipped, and is unpacked once into
`~/.terra/cache/vmlinux-<hash>` (the name is the hash of the embedded bytes, so
later boots reuse it and a terra upgrade prunes the one it replaces).

> Building libkrunfw compiles a full Linux kernel (needs `flex`, `bison`, `bc`,
> `libelf`, `openssl` dev headers, and Python `pyelftools`) — slow on first
> build, then cached.

## How it works

A box's guest root is a single bounded ext4 image, its `rootfs.img`, and terra
does not build it at run time: the image is baked at **build** time by the
Makefile (`mke2fs -d` writing the Alpine tree into it, inside a user namespace so
it lands root-owned) and shipped inside the binary, gzipped. Creating a box is
therefore a decompress plus a `set_len` — no mkfs, no privilege, no network, and
nothing fetched per machine — which is what lets a non-Linux host create one. The
guest grows the filesystem to `hw.rootfs_mib` on first boot, with the `resize2fs`
that rides the boot volume.

Booting is two-stage, and no host directory takes part in it. libkrun boots the
guest on the **boot volume**: a small read-only ext4 image, identical for every
box, holding nothing but the agent and `resize2fs`. The kernel roots on it
(`root=/dev/vda ro init=/terra-agent`) and runs the agent as PID 1 — no virtiofs
root, and no initramfs alternative either (`CONFIG_BLK_DEV_INITRD` is unset in
libkrunfw's kernel). Being a constant, the image is unpacked once into
`~/.terra/cache/` and shared by every box, like `vmlinux`.

Stage one is the agent on that volume: it mounts the pseudo-filesystems, dials
the host over vsock for its **boot plan**, grows every image to its configured
size (the root and each volume — `resize2fs` is out of reach after this point),
then mounts the box's root at `/dev/vdb` and chroots into it. There is no
re-exec: the process is already mapped, and the old root simply becomes
unreachable, which is what keeps the boot volume out of a running sandbox's `df`.
Stage two drives the guest's own tools (`mount`, `ip`, `chroot`) for the rest of
the setup, bakes `on_create` if the stamp inside the root is stale, then runs the
hooks and the workload. One integrated Rust process owns the whole guest
lifecycle.

Everything host and guest still have to say to each other goes over **one vsock
connection**, opened by the guest as its first act:

- the host answers it with the boot plan — so the sandbox's environment, secrets
  included, reaches the guest through memory and is never written to a file
- the same connection carries the one-byte graceful-stop signal behind
  `terra stop` and `systemctl stop` (a single `write`, which is what makes it
  usable from a signal handler)

The `on_create` bake needs no channel at all: the guest records the script it baked
at `/terra/recipe` **inside its own root filesystem** and compares it against the
plan on the next boot. The host never reads it — which is why seeding no longer
forks a second VM: a bare `terra setup` boots one to bake on demand, and a start
lets the same bake happen on its way to the workload.

A running sandbox therefore has exactly the host filesystem its config asked for
and nothing else: `mount` shows `/dev/vdb` (the bounded root), the volumes, the
pseudo-filesystems, and any shares you configured. A box with no `mounts` and no
project directory touches no host filesystem at all.

The guest kernel is compiled into the binary (statically linked, not
`dlopen`ed). A virtio-net NIC is bridged over a socketpair to an in-process
[`smolvm-network`](https://github.com/cryi/smolvm) gateway, which terminates the
guest's traffic and reopens host sockets under the configured egress policy
(DNS-answer learning for allowed hostnames, plus static IP/CIDR rules). Adding a
real NIC disables libkrun's TSI backend, so the gateway is the only network path
out of the guest.

## Platform support

The guest is always Alpine Linux, built for the same CPU as the host — a box
runs on the hardware the host runs on, so `make` derives `ARCH` from `uname -m`
and builds the kernel, the rootfs and the agent for it. Both Linux archs are
built natively in CI.

`make cross` is the separate case: it cross-builds the *host* binary with
[`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild) and does **not**
rebuild the guest set, so its output embeds the building machine's guest images.

| target | state |
|--------|-------|
| `x86_64-unknown-linux-musl` | supported — builds, boots, e2e green |
| `aarch64-unknown-linux-musl` | builds natively (`make ARCH=aarch64` on arm hardware); boot suite not yet run on arm. Not a `make cross` target: an x86_64 build host would pair an arm binary with an x86_64 guest |
| `aarch64-apple-darwin` | compiles end to end; the final link needs the macOS SDK for the `Hypervisor` framework (set `SDKROOT`) |
| `x86_64-apple-darwin` | libkrun has no Intel-Mac hypervisor backend (its HVF code is aarch64-only), so this needs work upstream that is not a packaging fix. libkrun on macOS is Apple Silicon only |
| `x86_64-pc-windows-gnu` | terra itself compiles (verified against libkrun's declared Windows API); libkrun does not. See below |

**Windows** is a libkrun question, not a terra one. Upstream ships the WHP API
bindings, the console handles and a complete `fs/windows` passthrough, but the
VMM never drives WHP (`vmm/src/` has `linux/` and `macos/` only, and
`device_manager/` has no `whp/`), and the vsock and virtio-net backends are
`nix`-only. Three dependency-level blockers sit underneath that: `krun-cpuid` is
declared for all of x86_64 though it needs KVM, `vm-memory`'s `rawfd` feature is
enabled unconditionally though the crate hard-errors on Windows, and
`linux-loader` pulls `vm-memory` with default features so that `rawfd` cannot be
turned off downstream — the last one wants a PR to rust-vmm.

None of that is in terra's way: its own sources are Windows-clean, so the day
libkrun's device and VMM layers land, the port is a dependency bump.

One thing in terra is Unix-only, and knowingly: **stopping a box is a signal.**
`terra stop` sends `SIGTERM` to the pid in the box's `terra.pid`, which the VM
process's handler turns into the one-byte stop on the control connection — the
same path `systemctl stop` takes, which is why there is only one. Windows has no
equivalent: `TerminateProcess` is `SIGKILL` with no `pre_stop`, and console
control events only reach a process sharing the console, which a detached VM does
not. That port will need a signalling channel of its own for the graceful half —
a named event a thread waits on, standing in for the handler that writes the
stop byte here — with the hard kill left to `TerminateProcess`. The note lives
on `sys::signal_pid`.

That pid lives in the file the box's lock is taken on — one file, so a pid read
under a held lock is that holder's by construction rather than by anyone
remembering to sweep a stale one. Nothing but `terra rm` ever unlinks it: the lock
is on the inode, so replacing the file would leave the next `terra` locking a
different one. This is the second thing a Windows port has to look at — a
`LockFileEx` range is *mandatory*, so while the lock is held nothing else can read
the file at all; locking a range past the end of the file is the way to keep the
pid readable there.

Everything else where the hosts genuinely differ lives in one module,
[`crates/terra/src/sys.rs`](crates/terra/src/sys.rs)
— unix sockets (std has them on Unix, `uds_windows` on Windows), file modes, and
the SIGINT/SIGTERM stop handler. Everything else is plain std: the box lock is `File::try_lock`
(`flock` on Unix, `LockFileEx` on Windows), a run spawns a background copy of
terra rather than `fork`ing (an interactive run then attaches to it, which is
what makes detaching possible at all), `terra logs -f` follows the file itself rather than shelling out to
`tail`, and the attached session drives the terminal through `crossterm`. The only
other `cfg` in the crate is in the libkrun FFI wrapper, where libkrun's own API
differs (console descriptors are kernel handles on Windows).

The filesystem work that genuinely needs Linux happens inside the guest.

## Release gate

`cargo test` covers config parsing, egress-policy construction, boot-plan
construction, and e2e CLI behavior (exit codes, stdout/stderr) — but not a real
boot. Before tagging a release, run the boot suite on a host with `/dev/kvm`
(CI runs it on every push):

```sh
make dist
TERRA_BIN=$PWD/dist/terra cargo test -p terra --test boot -- --ignored
```

The suite is an ordinary `#[ignore]`d cargo integration test
([`crates/terra/tests/boot.rs`](crates/terra/tests/boot.rs)); config assets live
in [`crates/terra/tests/assets/`](crates/terra/tests/assets/). It boots real
microVMs and asserts what unit tests can't:

- **egress** — an allowlisted host is reachable, an unallowed one is blocked.
- **ownership** — the workload runs as terri (or uid 0 under `--root`), but the
  filesystem *always* maps to terri: `/work` and volumes are terri-owned and
  writable, files land owned by the launching host user, and `--root` changes only
  the exec uid, never the on-disk ownership.
- **ports + isolation** — one VM publishes a port; a second VM reaches it *only*
  with a `hosts:` record naming the host plus the `allow:` rule opening that
  port, and a third VM with neither is blocked (the always-on egress floor).

## Troubleshooting

- **`failed to find tool "x86_64-linux-musl-gcc"`** — `zig` isn't on `PATH`.
  The musl C toolchain is provided by `zig` via `scripts/zig-musl-*`.
- **link error building `terra`** — the kernel ELF isn't built yet. Use
  `make build` to build `vmlinux` first.
- **kernel build fails** — missing kernel build deps (`flex`, `bison`, `bc`,
  `libelf`/`elfutils`, `openssl` dev headers).
- **the guest can't reach anything** — the default mode is `allowlist` with no
  rules, which is *no network*. The boot banner says which posture is in force;
  add `allow:` rules to the recipe, or set `mode: unrestricted-public`, then
  `terra setup` to re-pin it.
- **a connection is blocked and you don't know why** — run `terra logs`.
  A blocked *name* logs `virtio-net: blocking DNS query by allow-host policy
  name=…`, which is the rule you are missing; a connection to a bare IP logs
  `virtio-net: blocking outbound connection by egress policy` with the
  destination, so add that address or CIDR and retry.
