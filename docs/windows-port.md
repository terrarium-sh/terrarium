# Windows support: what it takes to build `terra.exe`

Verified 2026-07-27 with `cargo check -p terra --target x86_64-pc-windows-gnu`
against the vendored libkrun (`vendor/libkrun`, cryi mirror of upstream main,
rev `574cc39b`).

**Verdict:** terra's own code is Windows-ready as-is — no changes needed in
`crates/terra`. The vendored mainline libkrun is **not** buildable for Windows
yet: `src/whp/` is only the Windows Hypervisor Platform *bindings* crate
(partition / vCPU / instruction-emulator wrappers); the VMM driver that would
use it does not exist upstream. `vmm/src/lib.rs` compiles only `mod linux` and
`mod macos` — on a Windows target there is no `Vm`/`Vcpu` implementation at all.

Two routes to a working `terra.exe`:

- **Route A** — finish the port in `vendor/libkrun` (our fork exists exactly so
  these patches have a home). Layers 1–3 below, in order of effort.
- **Route B** — point terra at `smol-machines/libkrun`, which already carries
  the complete port. This route was verified end-to-end earlier today and
  produced a real `terra.exe` (PE32+), with Linux boot e2e still 18/18.

---

## Already in place (no work)

- **terra**: every platform difference is isolated in
  `crates/terra/src/sys.rs` and `src/vm/libkrun_ext.rs` (AF_UNIX via
  `uds_windows`, `SetStdHandle` stdio hand-over, stop-file instead of signals,
  ACL-inherit instead of modes). The Windows deps are already in its
  `Cargo.toml`.
- **vendored libkrun** already ships: `src/whp` (bindings, complete), arch
  x86_64 Windows boot setup, `devices/src/virtio/fs/windows/passthrough.rs`
  (full 2655-line virtiofs backend), console `port_io/windows`, ioapic wired to
  whp, utils' Windows epoll/eventfd emulation.

## Route A, layer 1 — four small gates (verified: they unblock everything above `krun-devices`)

1. `vendor/libkrun/src/utils/src/windows/bindings.rs:16` —
   `extern "system"` → `unsafe extern "system"`. Edition-2024 requirement; the
   file has never compiled. (Same crate also has ~6 fixable
   `unsafe_op_in_unsafe_fn` warnings in `utils/src/time.rs`.)
2. `vendor/libkrun/src/devices/Cargo.toml` — vm-memory's `rawfd` feature is
   Unix-only (`compile_error!` on Windows). Drop it from the unconditional dep
   and re-add under `[target.'cfg(unix)'.dependencies]`:
   ```toml
   [dependencies]
   vm-memory = { version = "0.17", default-features = false, features = ["backend-mmap"] }
   [target.'cfg(unix)'.dependencies]
   vm-memory = { version = "0.17", default-features = false, features = ["backend-mmap", "rawfd"] }
   ```
3. `vendor/libkrun/src/vmm/Cargo.toml` — the `cpuid` dep is KVM-shaped
   (imports `kvm_bindings` unconditionally) and is only used by
   `vmm/src/linux/vstate.rs`. Move it from `cfg(target_arch = "x86_64")` to
   `cfg(all(target_arch = "x86_64", target_os = "linux"))`.
4. **linux-loader** (crates.io 0.13.2) enables vm-memory's default features →
   `rawfd` leaks back in through feature unification; not fixable from
   downstream. Its own `[dependencies.vm-memory]` needs
   `default-features = false` (verified compiling). Needs a PR to
   rust-vmm/linux-loader; until released, a `[patch.crates-io]` fork (1-line
   change). Also add `default-features = false` to vmm's `linux-loader` dep.

## Route A, layer 2 — `krun-devices` Unix plumbing (133 errors remain after layer 1)

All in `vendor/libkrun/src/devices/src/`:

| Cluster | Errors | What it is |
|---|---|---|
| `virtio/bindings.rs` | 80 | Linux-ABI struct defs (`stat64`, `statvfs64`, fuse ABI) that the *existing* Windows passthrough fills — they just were never defined off-Linux |
| vsock TSI (`tsi_stream`, `tsi_dgram`, `unix.rs`, `muxer`, `proxy`) | ~40 | `nix` sockets, `libc::iovec`, `AF_*` constants |
| net backends (`unixstream.rs`, `unixgram.rs`, `backend.rs`) | ~25 | `std::os::unix::net` → needs socket2/uds port |
| `file_traits.rs`, `linux_errno.rs`, `legacy/i8042.rs` | ~25 | raw-fd I/O traits, errno table, reboot exit |

A finished 2893-line patch for this layer exists from today's earlier session
(measured: 136 → 4 errors) at
`/tmp/claude-1000/-home-v-projects-alis-is-terrarium/6f4eab95-e7c9-49af-802d-55d6f0f9fa96/scratchpad/libkrun-windows-port.patch`
(session-temp — copy it somewhere durable if Route A is chosen). It contains
the fs ABI glue, the socket2 virtio-net port (cherry-picked from smol-machines
`9edf078a` + `6a7e770e`), an opt-out `tsi` Cargo feature, and the portable
vsock host-IPC path. The residual 4 errors are structural: `vsock/packet.rs`
keeps `nix::SockaddrStorage` inside the TSI request structs (~15 sites; needs a
portable `VsockAddr` type).

## Route A, layer 3 — the gating item: no Windows VMM driver

Missing entirely upstream:

- `vmm/src/windows/` — vstate: create `WhpVm` partition, map guest memory, spawn
  vCPU threads, run-loop dispatching `IoPortAccess`/`MemoryAccess` exits into
  `WhpEmulator`, CPUID/MSR exit handling, external-kernel (vmlinux ELF) load.
- `vmm/src/device_manager/whp/` — MMIO/PIO bus for the emulator callbacks.
- The `#[cfg(windows)]` arm of `krun_start_enter` in `libkrun/src/lib.rs`
  (builder.rs already has partial Windows wiring: console port autoconfig,
  terminal raw mode).

Reference implementation: the smol-machines fork carries ~922 lines here
(`vmm/src/windows/vstate.rs` 612, `device_manager/whp/mmio.rs` 287), entangled
with their snapshot/fork feature — port or write fresh against `src/whp`'s API.

## Route B — use the fork that already works

```toml
libkrun = { git = "https://github.com/smol-machines/libkrun", rev = "…",
            default-features = false, features = ["net", "blk"] }
```

1. Root `[patch.crates-io]`: `linux-loader` **and** `vm-memory` → the fork's
   `vendor/` copies (both required; a git dep's own `[patch]` doesn't reach us).
2. `cargo update -p vm-memory --precise 0.17.1` — otherwise imago resolves
   0.18.0 and two vm-memory copies break `krun-devices` trait bounds.
3. One real blocker: the fork breaks on **musl** —
   `vmm/src/linux/vstate.rs` passes `KVM_KVMCLOCK_CTRL: c_ulong` to
   `libc::ioctl`, whose request arg is `c_int` on musl. Fix is `as _` at the
   call site; needs a PR to the fork (can't patch a file inside a git dep).
4. Trade-offs: fork is ahead of upstream (balloon, checkpoint/fork, vsock
   `dns_filter`) and diverges; two patched registry crates enter our graph.
   Bonus: its `krun_init_log(i32)` is portable, so the `#[cfg(unix)]`
   special-case in `vm/libkrun_ext.rs` could go away.

## Toolchain (cross-compiling from Linux)

- `rustup target add x86_64-pc-windows-gnu` (installed) + `cargo zigbuild`
  (installed; handles the C deps — bzip2-sys/zstd-sys fail with a bare
  `CC=zig cc` because cc-rs passes rust-style `--target=x86_64-pc-windows-gnu`,
  which zig rejects; zigbuild's wrappers rewrite it).
- Link-time shims (from the earlier verified build): `-Cdlltool=` zig shim, and
  a generated `libsynchronization.a` from a 3-export .def (`WaitOnAddress`,
  `WakeByAddressAll`, `WakeByAddressSingle`) — zig's bundled mingw lacks it,
  windows-sys needs it.
- Building natively on a Windows runner with MSVC avoids all shims.
- Consider `default-features = false` on the libkrun dep for Windows builds:
  the default `init-blob` feature cross-compiles libkrun's guest init for
  x86_64-linux-musl in a build script (an extra toolchain requirement), and
  terra boots its own agent as PID 1, never `init.krun`.

## Scope limits

- x86_64 hosts only — the whp crate uses `core::arch::x86_64`; no Windows-on-ARM.
- Runtime requirement: the "Windows Hypervisor Platform" optional feature must
  be enabled on the host (`WHvGetCapability` probe fails otherwise).
- Guest stays Linux x86_64 (hardware virt, ISA matches host) — the existing
  embedded vmlinux works unchanged.
