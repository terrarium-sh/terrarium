# Remaining work

Terra currently has a Linux x86_64 KVM implementation with WASI components for
boot, block, filesystem, network, vsock, memory, and the VMM. The production
transport is a bounded scalar bridge between independent Wasmtime stores; shared
memory, GPU, DAX, PCI, snapshots, whole-box fuel metering, and host-pressure
reclamation are deferred unless a measured requirement justifies them.

This is an implementation and acceptance backlog. An item is complete only
when its stated acceptance condition has been recorded with the relevant test
or host result. Build-only and cross-compilation checks do not establish native
VM behavior.

## Product acceptance

- [x] **Fresh Linux x86_64 KVM acceptance:** the 2026-09-13 packaged build
  passed all 9 boot, memory, and native workflow gates, including rootless
  Podman and two running boxes sharing host files. All 12 platform KVM gates
  passed, plus 5 repeated two-vCPU network/storage/restart runs. The review
  fixed TCP truncation at host EOF and a native-cleanup mutex stall.
  Commands, artifact hash, results, and validation limits are recorded in
  [Linux amd64 acceptance](linux-amd64-acceptance.md).

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

- [x] **Guest workflow compatibility:** make rootless Podman work for the
  ordinary Alpine user without granting host TUN access or host privileges.
  Start from the existing TUN/namespace setup in
  [`kernel/terra.config`](../kernel/terra.config) and the guest initialization in
  [`crates/terra-agent/src/init.rs`](../crates/terra-agent/src/init.rs). Add an
  ignored native-boot gate that creates and stops a rootless container on a
  private disk, proves allowed egress, and proves existing denials remain.
  The ignored `native_boot_runs_rootless_podman_on_a_private_disk` gate passed
  on Linux/KVM outside the sandbox on 2026-09-13 (55.03 seconds). It covers two
  boots, image import, persistent private storage, fresh runtime state, allowed
  egress, denied loopback/metadata destinations, read-only mounts, stop, and
  denied privilege escalation. Fixes preserve vsock lifecycle policy across
  guest reset, provide descriptor-based share statistics on Linux, macOS, and
  Windows hosts, and mount `/run` as tmpfs. Windows reports unavailable inode
  counts as zero. Native macOS/Windows Podman acceptance still needs those hosts.
  `make dist` passed; tested binary SHA256:
  `49b39ff5f125f48e9ba8492afee402b89b5117325fd6b2dcc4951f8d02c60c3d`.
  Both native acceptance gates passed again together (51.15 seconds), and
  `make verify` passed, using `TMPDIR=$PWD/build/t`.
  Run `make dist && mkdir -p build/t && TMPDIR=$PWD/build/t
  TERRA_BIN=$PWD/dist/terra cargo test -p terra --test
  native_boot native_boot_runs_rootless_podman_on_a_private_disk -- --ignored
  --nocapture`. Workspace temporary storage avoids this host's `/tmp` quota.

## Filesystem and I/O correctness

- [ ] **Mount coherency contract:** define cache and writeback behavior for
  host and other-box changes through open files, directory listings, mappings,
  rename, truncation, and fsync. Test it through the filesystem worker
  ([`components/fs`](../components/fs)) and real guests. Document polling for
  editors; host-to-guest notification bridging is intentionally absent.

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
  and delivery is [`components/vsock`](../components/vsock).

- [ ] **Measured performance:** use matched previous/current binaries and real
  Git/build, parallel CPU, concurrent network, storage, and multi-box workloads
  to measure setup, ready time, throughput, tail console latency, CPU, RSS,
  MMIO/KVM-exit costs, and shutdown. Investigate the known mount-throughput and
  intermittent CPU-count-hook failures only if reproduced. Keep drivers under
  [`scripts/bench-vmm.py`](../scripts/bench-vmm.py) and
  [`scripts/bench-shared-irqs.py`](../scripts/bench-shared-irqs.py).

## Containment and sustained operation

- [ ] **Native resource limits:** define enforceable per-box CPU, native-memory,
  persistent-disk, bandwidth, and connection limits beyond existing admission,
  fixed disk extents and capped logs. Test exhaustion and peer isolation.
  Clearly distinguish Terra's current component
  memory/admission limits from deployment-owned hard native and kernel-memory
  limits. Relevant admission and worker code is
  [`crates/terra/src/vm/resources.rs`](../crates/terra/src/vm/resources.rs) and
  [`crates/terra-runtime/src/box_runtime.rs`](../crates/terra-runtime/src/box_runtime.rs).
  Document the required deployment-owned OS controls for hard worker/process
  and kernel-memory containment.

- [ ] **Grant revocation and recovery:** specify and test revocation of network,
  mount, and service access, including existing connections and open handles.
  Define crash/restart recovery, bounded backoff, and host-owned audit events
  that exclude secrets and treat guest output as untrusted. Add a narrow broker
  only where destination grants cannot constrain an approved operation.

- [ ] **Adversarial validation:** extend [`fuzz/fuzz_targets`](../fuzz/fuzz_targets)
  beyond network policy, native memory, device queues, FUSE, vsock headers, and
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
