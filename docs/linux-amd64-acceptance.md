# Linux amd64 acceptance

The latest Linux review is recorded in [2026-10-02 review](#2026-10-02-review).
The [cross-platform follow-up](#cross-platform-follow-up) tracks the remaining hosts.

Review and local acceptance on 2026-09-13, using an AMD Ryzen 7 5700G
(16 logical CPUs), Linux `7.2.2-1-default`, and host KVM. The artifact is a
stripped, statically linked x86-64 Linux executable built by `make dist`.

Binary SHA-256:
`f4b181bbcabd773720619c0288f2795bd9928baacf45f7d2b1627ef6c8ae3191`.

## Fixes

- Native cleanup released its state mutex only after blocking shutdown finished.
  Another cleanup waiter could therefore block an async executor thread. The
  reaper now takes the task under the lock and runs shutdown after unlocking.
  `stalled_cleanup_releases_the_state_lock_for_other_waiters` pins that ordering.
- Outbound TCP aborted the guest socket at host EOF, discarding queued response
  bytes. The 65,537-byte KVM download test failed both in the full suite and in
  isolation. Host EOF now closes the send direction gracefully, retaining
  unacknowledged bytes and the opposite direction until completion. Errors and
  cancellation still abort. Unit tests cover pending response bytes and both
  half-close orders; the formerly failing KVM test passes.
- The new `native_boot_shares_host_changes_between_running_boxes` gate exercises
  two live boxes sharing a host directory. Eight rounds check host replacement,
  guest truncation, create/delete visibility, read-only enforcement, and reader
  operation after writer shutdown. The fixture places host CLI arguments before
  the guest command so `exec --` cannot consume them.
- Network-policy fuzzing exposed a stale assertion that expected unrestricted
  egress to resolve malformed hostnames. The runtime correctly denied those
  names. The harness now requires denial for invalid names and retains a
  minimized nine-byte corpus regression; its formatting and strict Clippy checks
  passed after the correction.

## Verification

Commands run outside the tool sandbox to access KVM, Podman, and compiler
caches. `TMPDIR` uses project storage; the host's temporary-storage limits can
otherwise interfere with VM fixtures.
Local run logs are retained under `build/linux-amd64-acceptance-2026-09-13/`.

```sh
mkdir -p build/t
TMPDIR=$PWD/build/t make dist
TMPDIR=$PWD/build/t make verify
TMPDIR=$PWD/build/t cargo test --locked -p terra-platform \
  --target x86_64-unknown-linux-musl --lib -- --ignored --nocapture
TMPDIR=$PWD/build/t TERRA_BIN=$PWD/dist/terra cargo test --locked -p terra \
  --target x86_64-unknown-linux-musl --test boot --test memory --test native_boot \
  -- --ignored --nocapture --test-threads=1
```

| Gate | Result |
| --- | --- |
| Packaged build | Passed |
| Full `make verify` after fixes | Passed; 796 Rust tests passed across 52 suites, 23 ignored |
| Platform KVM integration | 12 passed, including large TCP, upload, published ports, mounts, agent lifecycle, and page reporting |
| Packaged boot, memory, native workflow gates | All 9 passed: 5 boot tests (73.30 s), memory growth/reclamation (28.78 s), 3 native workflow tests (54.79 s), including rootless Podman across two boots |
| Repeated two-vCPU network/storage/restart gate | 5 additional runs passed, each checking two boots |
| Network component units | 26 passed |
| Native reaper units | 5 passed |
| RustSec audit | All 11 committed lockfiles passed with cargo-audit 0.22.1 and a refreshed database |
| Sanitizer fuzz smoke tests | All 6 targets passed one-minute runs; network policy passed after correcting the harness assertion |

Fuzz commands use the pinned nightly and existing harnesses:

```sh
TMPDIR=$PWD/build/t cargo +nightly-2026-09-07 fuzz run TARGET -- \
  -max_total_time=60 -max_len=32768
```

Targets: `device_queue`, `native_memory`, `fuse_wire`, `vsock_header`,
`protocol_frames`, and `network_policy`. These are bounded smoke tests, not
exhaustive adversarial validation.

## Scope

This records local Linux amd64 acceptance, not validation of other hosts.
Systemd deployment, commits, and pushes were excluded. Other architectures,
multi-day stress, independent security review, power-loss testing, suspend/resume,
and matched performance comparisons remain in [the backlog](todo.md).
The [documented resource limits](security.md) and
[mount coherency limitations](recipe.md#mounts-and-environment) still apply.

## 2026-10-02 review

Security and maintainability review on Linux `7.2.7-1-default`, AMD Ryzen 7
5700G (16 logical CPUs), with host KVM. The review covered filesystem grants,
network authorization and DNS, guest protocols and agent services, native VM
memory and device imports, shutdown, Linux containment, CLI state/storage/sync,
dependencies, build/release tooling, and the static website.

`make dist` produced the statically linked, stripped `terra dev+eb31d2c4` binary.
SHA-256: `83e79f10c221ac7584f8f76b22ec014e50f16cc605b7e25111d0a5d0929acfc6`.

Confirmed fixes:

| Area | Problem | Correction |
| --- | --- | --- |
| Native DNS | Cancelling a lookup released admission while its blocking resolver continued; repeated cancellation could exceed the eight-lookup limit. | The blocking task owns the permit until resolution finishes. The caller retains its two-second timeout. |
| DNS wire responses | Echoed compression pointers could reference omitted query bytes and form a compression loop. | Success and error replies encode self-contained questions, preserving label boundaries and case. |
| Filesystem hardlinks | Unlinking one name invalidated a cached surviving alias; stale names could select a replacement inode. | Validate cached paths against inode identity and remove unconditional invalidation. Unlinked paths report `ENOENT`. |
| Vsock listener | Reaching client or resource-table capacity returned an empty completed read, permanently ending the listener. | Reject the excess connection while leaving the listener pending. |
| Vsock half-close | Echoing sender-relative shutdown flags closed the guest's opposite direction. | Preserve the remaining direction without echoing shutdown flags. |
| KVM shutdown | An exhausted shared deadline classified already-finished vCPUs as stuck. | Consume queued completion before reporting timeout. |
| Agent handshake | A connection closed during the version byte was reported as an incompatible protocol. | Read the complete hello before validating it; retry partial connections. |
| Windows stdin | Redirected files and closed pipes never became ready, hanging command input or EOF. | Recognize regular files and pipe closure. |
| Inherited environment | Non-UTF-8 host environment entries panicked during `exec --inherit-env`. | Skip entries that cannot be represented by the UTF-8 wire protocol. |

Each behavior change has regression coverage. No host escape or destination
policy bypass was confirmed in the reviewed paths. This is source review and
local testing, not an independent security assessment.

The Ponytail pass removed the uncompiled 263-line VMM scheduler, unused interrupt
delivery bookkeeping and native helpers, and duplicated benchmark hashing loops.
Generated hash-named fuzz corpus entries now use the existing ignore rule for
all targets. No dependencies were added. The root lockfile replaces yanked
`yoke-derive` 0.8.3 with 0.8.4; the other lockfiles already used an unyanked version.

Builds and most native tests used `TMPDIR=$PWD/build/t`. Packaged tests need a
short temporary path with enough disk space for guest fixtures; `/tmp` worked
for the network-test retry below. Local logs and generated fuzz inputs are
retained under `build/audit/`.

| Gate | Result |
| --- | --- |
| `CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 make verify` | Passed: 1,084 Rust test executions across 55 suite invocations, including repeated platform checks; formatting, strict Clippy, documentation and build-script checks passed. |
| RustSec audit | All three committed lockfiles passed with a refreshed database, without advisory or yanked-package warnings. |
| Website | Production build, type check and all four tests passed; dependency audit reported zero advisories. |
| Sanitizer fuzz smoke | All six existing targets passed; 30,511,122 inputs in total, with 60-second run budgets (network-policy corpus initialization completed after 71 seconds). |
| Native platform KVM | Both platform unit gates and all three native VM lifecycle gates passed. |
| Runtime KVM | All 12 boot, filesystem, network, agent and memory gates passed. |
| Native Bubblewrap probe | Passed filesystem denial, host-loopback behavior and seccomp inheritance checks. |
| Packaged KVM acceptance | All 11 boot tests passed, including the network-test retry below; memory growth/reclamation and all seven native workflow tests passed, including rootless Podman and two boxes sharing host files. |
| Enforced sandbox | The packaged VM/vCPU containment test passed with `TERRA_SECCOMP_ENFORCED=1`, using Bubblewrap and the built-in seccomp policy. |
| Windows cross-compilation | CLI library and tests passed `cargo check --target x86_64-pc-windows-gnu` using Zig; Windows execution remains unverified. |

The existing watcher-startup test timed out once under default test concurrency
while sanitizer compilation was running. Its five-second deadline includes
fixture construction and Wasm compilation; the test passed in isolation and in
the full four-thread verification. Neither its deadline nor the production
watcher timeout changed.

The packaged boot suite initially passed ten tests and rejected the network
fixture before VM startup: its workspace temporary directory produced a
111-byte control socket path, exceeding the 107-byte limit. The same compiled
test passed with `TMPDIR=/tmp`; the path guard and test were unchanged. The
reproduction commands below use the shorter path for packaged tests.

Reproduce the native gates against the packaged binary:

```sh
TMPDIR=$PWD/build/t CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 make verify
TMPDIR=$PWD/build/t CARGO_BUILD_JOBS=4 make dist
TMPDIR=$PWD/build/t cargo test --locked --target x86_64-unknown-linux-musl \
  -p terra-platform --lib --test native_vm -- --ignored --test-threads=1
TMPDIR=$PWD/build/t cargo test --locked --target x86_64-unknown-linux-musl \
  -p terra-runtime --lib boot_tests:: -- --ignored --test-threads=1
TMPDIR=/tmp TERRA_BIN=$PWD/dist/terra cargo test --locked \
  --target x86_64-unknown-linux-musl -p terra --test boot --test memory \
  --test native_boot -- --ignored --test-threads=1
TMPDIR=/tmp TERRA_BIN=$PWD/dist/terra TERRA_SECCOMP_ENFORCED=1 \
  cargo test --locked --target x86_64-unknown-linux-musl -p terra --test boot \
  bwrap_enforces_vm_and_vcpu_threads -- --exact --ignored --test-threads=1
TMPDIR=$PWD/build/t cargo test --locked --target x86_64-unknown-linux-musl \
  -p terra --lib sandbox::linux::bwrap::tests::production_jail_restricts_native_probe \
  -- --exact --ignored
```

This acceptance is limited to Linux amd64 on this host. AArch64, macOS and
Windows native acceptance, multi-day stress, power-loss recovery and independent
security review remain in [the backlog](todo.md). Hard aggregate OS resource
limits and network restrictions that survive native VM compromise remain
deployment responsibilities described in [the security model](security.md).

## Cross-platform follow-up

The follow-up review covers all five supported host targets. Native acceptance
outside Linux x86_64 is still pending; compiler checks and emulation do not
establish hypervisor behavior.

| Area | Confirmed defect and fix |
| --- | --- |
| ARM guest timer | The device tree swapped the nonsecure physical and hypervisor timer interrupts. It now declares the binding's ordered INTIDs 29, 30, 27 and 26. The existing FDT regression fails with the old ordering. |
| macOS CPU lifecycle | `CPU_OFF` destroyed an HVF vCPU in a running GIC topology. Power cycles now retain the native handle and restore boot controls on `CPU_ON`; shutdown rejects new starts and preserves worker ownership until join. |
| macOS failure reporting | Native worker errors bypassed the runtime failure callback. Installed handlers now receive the failure, and preparation failures reach the startup channel. |
| Windows ARM startup | Secondary workers waited for software PSCI messages while Hyper-V handles PSCI internally. Every worker now enters WHP; `StartupSuspend` lets native `CPU_ON` release each secondary. The unused software-start channel was removed. |
| Windows native ABI | ARM register initialization and both architectures' exit buffers lacked required alignment. Retained buffers now have 16-byte alignment, with compile-time layout assertions. |
| Windows ARM poweroff | Native poweroff reported a generic stop. It now reports shutdown and cancels sibling CPUs. |
| Windows console lifecycle | Foreground console interrupts killed the VM through job closure, and detached workers retained their parent's console. Ctrl+C/Ctrl+Break now use the stop channel; detached workers use `DETACHED_PROCESS` while retaining explicit startup pipes. Raw-mode Ctrl+C remains guest input. |
| Windows stop-channel errors | The dependency's socket-pair constructor panicked on bind failures, including valid temporary directories exceeding the socket path limit. The shared constructor now returns setup errors through the existing VM cleanup paths, without starting a helper thread. A subprocess regression covers long temporary paths. |
| Windows run lock | The writer followed a reparse point before truncation. It now opens the link itself and rejects reparse or non-regular handles, matching Unix's no-redirection contract. |
| Release verification | Linux amd64 builds require platform, runtime and packaged native gates; releases also require its enforced default jail. Other platforms' VM gates are opt-in while native runners are unavailable, and the ARM64 policy job is optional. An explicitly requested gate fails if virtualization is unavailable. |

New Windows tests cover actual console-event delivery, detached startup pipes,
lock redirection, retained metadata-handle identity, native MMIO exits and ARM
PSCI startup. New macOS tests cover retained vCPU handles and reset controls.
These platform-specific tests pass compiler checks but still require native
execution. Console close, logoff and system shutdown retain
Windows default handling.

Local commands and logs are under `build/audit/platforms/`. Windows checks use
Rust 1.98.1, Clang/LLD 22.1.8, the Microsoft 10.0.26100 SDK and 14.44 CRT through
`cargo-xwin` 0.23.1. Both MSVC targets and ARM64 Linux pass workspace/all-target
strict Clippy and link all 31 test/example executables. Genuine C/Rust probes
also link against the SDK on both Windows architectures. The complete macOS
workspace passes strict Clippy using Zig's Darwin C toolchain. After the
stop-channel fix, the integrated `make verify` passes all 1,084 Rust test
executions across 55 suite invocations. Commands, exit codes and executable
architectures are recorded in `platform-validation-results.json` in that audit
directory. Cross-linked runtime binaries
still contain the local Linux x86_64 guest/AOT fixtures; native acceptance needs
a matching host build.

ARM64 Linux passes 72 platform/protocol tests under QEMU user emulation. The
guest-agent suite passes 82 of 84 tests; the two failures remain recorded. A
standalone C probe reproduces QEMU 11.1.1 returning a zero-length socket timeout
despite the host kernel returning 16 bytes. A separate parser probe measures
373–466 ms under QEMU versus 20–32 ms natively, exceeding the terminal test's
100 ms deadline before output I/O. Reproductions and logs are listed in
`linux-arm-qemu-agent-failure-diagnosis.json`; the tests were not weakened.

Windows x64 passes 36 protocol tests plus the run-lock and redirected-input
regressions under Wine 11.16. The console-relay test cannot run there because Wine
rejects Unix-domain sockets with `WSAEAFNOSUPPORT`; WHP is also unavailable.
None of these emulated checks establishes native Windows or ARM VM behavior.

The rebuilt Linux package has SHA-256
`ce62e1c9302556138e3150e2a7302ea82dc296565704f64e6e5db4cc45611cd4`.
All 38 native tests pass: five platform/lifecycle tests, 12 runtime boot tests,
the native sandbox probe, 11 packaged boot tests, memory reclamation, seven
native workflows and the explicitly enforced sandbox gate. Packaged fixtures
used `TMPDIR=/tmp`. Commands, per-gate exit codes and artifact identity are
recorded in `build/audit/platforms/native-results.json`.

| Supported host | Current worktree verification | Native acceptance |
| --- | --- | --- |
| Linux x86_64 | Full verification, release build and 38 native tests passed. | Passed locally. |
| Linux ARM64 | Strict Clippy, all 31 test links and 72 platform/protocol emulated tests passed; two agent emulation failures are recorded above. | Pending ARM64 KVM host. |
| Apple Silicon macOS | Workspace/all-target strict Clippy passed. | Pending entitled native Mac. |
| Windows x64 | MSVC strict Clippy, all 31 test links and 38 Wine tests passed. | Pending native Windows unit and WHP execution. |
| Windows ARM64 | MSVC strict Clippy and all 31 test links passed. | Pending native Windows unit and WHP execution. |

The last remote build at `eb31d2c4`,
[run 36964585471](https://github.com/terrarium-sh/terrarium/actions/runs/36964585471),
passed build/unit checks but skipped both Linux KVM gates and all macOS/Windows
native VM stages. On 2026-10-02, the repository runner API returned no configured
self-hosted runners and no runner-label variables. Native verification needs
Linux ARM64 KVM, entitled Apple Silicon Hypervisor.framework, and Windows x64
and ARM64 WHP hosts. The configuration and commands are in
[the development guide](../README.dev.md#verification).
Hosted CI for these changes has not been dispatched; publishing a separate
branch for that verification awaits authorization.
