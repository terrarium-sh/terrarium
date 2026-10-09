# Remaining work

The network transport uses [per-socket TCP and UDP vsock streams](../README.dev.md#network-transport);
its native gates on hosts other than Linux x86_64 remain open.

Terra currently has a Linux x86_64 KVM implementation with WASI components for
boot, block, filesystem, a combined vsock device/network frontend, a separate
agent store, memory, and the VMM. The production
transport is a bounded scalar bridge between independent Wasmtime stores; shared
memory, GPU, DAX, PCI, snapshots, whole-box fuel metering, and host-pressure
reclamation are deferred unless a measured requirement justifies them.

This is an implementation and acceptance backlog. An item is complete only
when its stated acceptance condition has been recorded with the relevant test
or host result. Build-only and cross-compilation checks do not establish native
VM behavior.

ARM timer, macOS lifecycle, Windows WHP/console/socket and release-gate fixes are
implemented; the corresponding native host gates below remain open until executed.

## Product acceptance

- [ ] **Linux AArch64 KVM:** run the packaged binary's boot, mount, networking,
  SMP, memory-reclaim, shutdown, and ARM GIC-routing gates on AArch64 hardware.
  Include CPU state, device ordering, and capacity behavior.
  Record the commands and results beside
  [`crates/terra/tests/native_boot.rs`](../crates/terra/tests/native_boot.rs) and
  [`crates/terra/tests/memory.rs`](../crates/terra/tests/memory.rs).

- [ ] **macOS and Windows:** run the native packaged-release gates on Apple
  Silicon macOS and both supported Windows WHP architectures. Cover boot,
  two-vCPU startup, granted networking, read-write and read-only mounts,
  persistent volumes, and orderly shutdown. On Windows, explicitly verify the
  reduced WASI mount contract, CPU state, and device ordering. The gate is
  [`crates/terra/tests/native_boot.rs`](../crates/terra/tests/native_boot.rs).

## Filesystem and I/O correctness

- [ ] **Mount coherency contract:** define cache and writeback behavior for
  host and other-box changes through open files, directory listings, mappings,
  rename, truncation, and fsync. Test it through the filesystem worker
  ([`components/fs`](../components/fs)) and real guests. Native event forwarding
  now covers host-to-guest notifications through virtio-fs without polling or
  recovery scans. Linux KVM acceptance passed on 2026-09-20 for direct and
  directory watches, atomic saves, read-only shares, box-to-box edits, and Node
  native watch-mode reload. Actual macOS and Windows acceptance remains open.

- [ ] **Concurrent mount workloads:** extend the existing one-guest Git, atomic
  save, executable, and mmap coverage in
  [`crates/terra/tests/boot.rs`](../crates/terra/tests/boot.rs) to cover concurrent
  host and other-box changes. Include visibility, read-only grants, cancellation,
  ENOSPC, reset, and shutdown under I/O.
  The 2026-09-13 native acceptance gate now checks host replacement, guest
  truncation, create/delete visibility, read-only enforcement, and one box
  stopping while another keeps using the share. I/O fault and saturation
  scenarios remain open.

- [ ] **Durability and lifecycle stress:** exercise every device under stalled
  or full queues, slow or failed I/O, cancellation, reset, and shutdown while
  other devices and boxes continue. Include power-loss recovery separately from
  successful `fsync`/`sync`. Extend the production-worker tests in
  [`crates/terra-runtime/tests`](../crates/terra-runtime/tests) and native gates
  where hypervisor behavior is material.

## Time and performance

- [ ] **Time and entropy:** measure guest clock startup, drift correction,
  suspend/resume, and clock jumps on every native backend. Define Windows
  timezone behavior and test TZif/DST handling. Audit early-kernel entropy and
  backend entropy readiness before hooks, TLS, or key generation. The wire
  contract is [`crates/terra-protocol/src/plan.rs`](../crates/terra-protocol/src/plan.rs)
  and delivery is [`components/agent`](../components/agent).

- [ ] **Measured performance:** use matched previous/current binaries and real
  Git/build, parallel CPU, concurrent network, storage, and multi-box workloads
  to measure setup, ready time, throughput, tail console latency, CPU, RSS,
  MMIO/KVM-exit costs, and shutdown. Investigate the known mount-throughput and
  intermittent CPU-count-hook failures only if reproduced. Keep drivers under
  [`scripts/bench/bench-vmm.py`](../scripts/bench/bench-vmm.py) and
  [`scripts/bench/bench-network.py`](../scripts/bench/bench-network.py).

## Containment and sustained operation

- [ ] **Native resource limits:** define enforceable per-box CPU, native-memory,
  persistent-disk, bandwidth, and connection limits beyond component ceilings,
  fixed disk extents and capped logs. Test exhaustion and peer isolation.
  Clearly distinguish Terra's current component
  memory limits from deployment-owned hard native and kernel-memory
  limits. Relevant worker code is
  [`crates/terra-runtime/src/box_runtime.rs`](../crates/terra-runtime/src/box_runtime.rs).
  Document the required deployment-owned OS controls for hard worker/process
  and kernel-memory containment.

- [ ] **Grant revocation and recovery:** specify and test revocation of network,
  mount, and service access, including existing connections and open handles.
  Define crash/restart recovery, bounded backoff, and host-owned audit events
  that exclude secrets and treat guest output as untrusted. Add a narrow broker
  only where destination grants cannot constrain an approved operation.

- [ ] **Adversarial validation:** extend [`fuzz/fuzz_targets`](../fuzz/fuzz_targets)
  beyond network policy, native memory, device queues, FUSE, channel framing, and
  protocol frames to native imports and control input. Prove cross-box RAM, file,
  network, control, and resource isolation during reset and teardown. Run
  multi-box exhaustion and multi-day stress on each native backend, then obtain
  an independent review of trusted grant enforcement and turn findings into
  regressions. Test the runtime and guest-kernel update and restart process for
  long-lived boxes. Preserve commands, artifact hashes, and host results with
  every native acceptance run.

## Deferred work

Do not start these without a concrete requirement and acceptance plan: shared
component memory/rings, accelerated GPU, PCI/MSI-X, DAX, snapshots, whole-box
Wasm metering, and host-pressure-driven reclamation. Private guest disks remain
the path for full Linux filesystem semantics.
