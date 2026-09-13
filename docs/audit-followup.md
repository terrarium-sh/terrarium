# Audit follow-up

Review of the supplied crates/components audit against the current code and
`AGENTS.md` threat model. Hardware boot tests require `/dev/kvm`, which is not
available in this environment.

## Security findings

| Finding | Disposition |
| --- | --- |
| S1: chmod privilege bits | Fixed: host share chmod accepts only `0o0777`; regression requests all special bits. |
| S2: duplicate YAML keys bypass provenance | Fixed: parse only mounts, ignore unrelated fields, and treat unreadable pinned recipes as uncertain authorship requiring approval. |
| S3: virtqueue extents | Fixed in shared transport: validate complete descriptor, available, and used rings with checked arithmetic before arming. |
| S4: interrupted `get` destroys destination | Fixed: stage the transfer and atomically replace only after its advertised length arrives. Existing regular-file symlinks retain their target semantics; dangling symlinks and special files are rejected. Guest-side symlink traversal is intentional for an operator-requested transfer, not a host escape. |
| S5: `put` grants ownership of ancestors | Fixed: newly created ancestors retain the agent's ownership; only the transferred file receives workload ownership. |
| S6: KVM teardown hangs | Fixed: unblock the kick signal in runner threads and bound Drop by the existing stop timeout. A timed-out runner retains its VM resources until it exits. |
| S7: internal boot entry point | Fixed the root guard by sharing it with setup. The stdin boot specification comes from the trusted host process; an additional arbitrary allocation limit would not establish a guest boundary. |
| S8: PID without start identity | Fixed on Unix and Windows: missing identity cannot authorize a signal. |
| S9: symlinked host state | No change: host state and host-local mutation are explicitly trusted/outside the threat model. Guest mounts cannot grant the Terra state tree. |
| S10: synchronous policy on event loop | Fixed: socket and DNS policy callbacks run off the async runtime thread with bounded admission; the isolated, fuel-limited, fail-closed policy worker remains. |
| S11: release inputs | Fixed: pin cargo-audit; restrict installer downloads to HTTPS and verify attestations when GitHub CLI is installed. Failed attestation stops installation. Include GPL text and corresponding-source archives for both guest architectures, using pinned Alpine package recipes and checksum-verified upstream sources. |

## Correctness findings

| Finding | Disposition |
| --- | --- |
| P1: host-loopback TCP reset | Fixed: listen on the guest-visible gateway destination, connect to host loopback. Regression exercises the SYN and checks both destinations. |
| P2: Windows missing components | Fixed: PowerShell reads the component list from Makefile, including boot and policy. |
| P3: reaper PID reuse | Fixed: preserve exit status by owned process identity and wait through pidfds, rather than assigning a reused PID's status to an old waiter. Daemon supervision shares the same handle without descriptor duplication. |
| P4: one unreadable project hides all boxes | Fixed: warn and skip that project's state. |
| P5: Legacy lifecycle default | No defect: the default supports older hosts talking to a newer agent. Current hosts explicitly request EventsV1 and do not need to decode Legacy replies. |
| P5: failed VM attachment | Fixed: release host attachment state and invalidate the failed Wasm instance; callers must use a fresh runtime after initialization failure. |
| P5: memory poison and small reports | No defect: reporting is a reclamation hint. The guest supplies poison; discarding nonzero-poison pages would replace it with zeros. Sub-host-page hints must not discard adjacent live guest pages. |
| P5: transient listener failure | Fixed: retry failed published listeners with a delay. |
| P5: saturated session input | Fixed: reject a full queue promptly rather than blocking a client thread. |
| P5: hook timeout descendants | Fixed: give hook shells their own process group and kill that group on timeout. Deliberately detached guest processes remain within the guest's authority. |
| P5: empty kernel patch list | Fixed: empty checksum input reads `/dev/null`, not interactive stdin. |
| P5: Intel macOS compilation | Fixed: gate Apple Silicon backend imports and preserve the unsupported-platform path. |

## Maintenance and scope

| Finding | Disposition |
| --- | --- |
| M1: state-to-command recovery cycle | Fixed: recover imports explicitly under the existing lock in box preparation, export, import, and prune. |
| M2: unsupported architecture constant | Fixed: unsupported VM architectures have zero available storage devices, so the stub compiles. |
| M3: duplicate queue walker | Fixed: network consumes the shared tested split-ring walker. Block also consumes shared descriptor constants. |
| M3: repeated device shells | No blanket extraction: device scheduling, state and capabilities differ, and the report identifies no additional behavior defect. |
| M3: guest-copy limit drift | Fixed: runtime and relevant devices use `terra-limits`. |
| M3: 253/254-byte names | Fixed: use one 254-byte input cap, accommodating a 253-byte hostname plus its terminal root dot. |
| M3: WIT duplication | Already shared through symlinks. Filesystem and memory worlds deliberately select different capabilities. |
| M4: large files | Review-cost observation, not a demonstrated defect; no wholesale dispatcher rewrite. |
| M5: test gaps | Add targeted regressions for changed behavior. CI fuzzes native memory; named seeds are now tracked. The earlier claim relied on local ignored corpus files. Exhaustive platform coverage and new fuzz projects remain separate work. |
| M6: documentation drift | Fix the demo link, boot-option documentation, removed policy-method comment and cached-download hash claim. Release panic behavior is deliberate; ignored local notes are not shipped documentation. |
| S11: reproducibility | No reproducibility guarantee is claimed. Provenance and reproducible output are distinct; deterministic ext4 images require more than fixing UUID and are separate build work. |

## Verification

- `make verify`: passed, including component builds, WIT checks, formatting,
  strict Clippy, documentation, installer/kernel/source-collector checks,
  workspace tests and shared-memory experiment tests. Rust test output totals
  727 passed and 28 ignored across 52 suites.
- `make source-dist`: passed with real downloads; checked the archive layout
  and inclusion of the kernel, e2fsprogs and Alpine corresponding sources.
- Collected Alpine sources separately from the SHA256-verified ARM64
  minirootfs; all five GPL source origins passed APKBUILD checksum checks.
- `cargo check --locked --workspace --target aarch64-unknown-linux-musl`:
  passed.
- `cargo check --locked -p terra-agent -p terra-protocol --target
  aarch64-pc-windows-msvc`: passed.
- The Windows workspace check stops in Wasmtime's C dependency because this
  Linux environment lacks Windows SDK headers (`windows.h`). Native Windows
  release execution and Intel macOS compilation were not available here.
- KVM boot tests could not run because `/dev/kvm` is absent.
