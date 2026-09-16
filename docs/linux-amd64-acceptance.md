# Linux amd64 acceptance

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
