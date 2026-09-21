# Terrarium development

Users start at the [README](README.md). Outstanding implementation and validation
work lives in [todo.md](docs/todo.md).

## Build

Linux builds need Rust (pinned by [rust-toolchain.toml](rust-toolchain.toml)),
Podman for kernel compilation, Zig for the musl C toolchain, Make, Python 3,
`curl`, `tar`, `gzip`, and `unshare`. Building guest filesystem images requires
working unprivileged user namespaces. Running Linux guests requires readable
and writable `/dev/kvm`.

Install the separate component toolchain and validator:

```sh
rustup toolchain install nightly-2026-09-16 --component rustfmt,clippy --target wasm32-wasip3
cargo install wasm-tools --version 1.248.0 --locked --target "$(rustc -vV | sed -n 's/^host: //p')"
make dist
```

`make dist` produces `dist/terra` with embedded guest images and trusted,
precompiled Wasmtime components, plus license notices. Linux releases target
static musl; ordinary Cargo commands use the native host target. Production
loads embedded AOT components without a Wasm compiler. Run image-building Make
targets sequentially in a shared checkout.

The guest is Alpine Linux on the host's CPU architecture. Guest images are
built on Linux; macOS and Windows builds consume those images and compile AOT
components for their own host target. See [native host builds](packaging/README.md#native-host-builds)
for staging, platform requirements, and signing. WIT packages share
[interface sources](components/wit/README.md) through symlinks; Windows
checkouts require symlink privileges and `core.symlinks=true`.

## Code layout

| Path | Responsibility |
| --- | --- |
| `crates/terra` | CLI, recipes and manifests, box storage, policy construction, VM launch and clients |
| `crates/terra-agent` | Linux guest initialization, hooks, workload and interactive services |
| `crates/terra-protocol` | Shared guest wire protocol |
| `crates/terra-network` | Shared network policy types and address rules |
| `crates/terra-platform` | Native VM, memory, filesystem and local-I/O APIs over KVM, Hypervisor.framework and WHP |
| `crates/terra-runtime` | Wasmtime stores, guest layout, scoped host capabilities and component/VM lifecycle orchestration |
| `components` | Boot planning, VMM and device protocols, network policy, transport and WIT |
| `kernel`, `pins.mk` | Guest kernel configuration and pinned build inputs |
| `fuzz`, `scripts` | Boundary fuzz targets, build checks and benchmark tools |

Runtime derives the fixed machine layout and asks platform to create the VM,
RAM, disks and vCPUs. A short-lived boot component plans kernel placement;
runtime validates its writes and result before CPUs start. The VMM component
then owns exit interpretation, MMIO routing and lifecycle decisions. Device
components run in independent stores and communicate through bounded scalar
bridges. Hypervisor operations and authority checks remain native. See the
[security model](docs/security.md) for trust boundaries and resource limits.

The agent starts as PID 1 from the read-only 3 MiB memory-backed boot disk, receives its boot
plan over vsock, grows the box's ext4 images and enters the Alpine root with
`pivot_root`. It applies `on_create` when its guest-side recipe stamp differs,
then configures mounts and runs hooks and the workload. Boot-plan environment
values are sent through memory, not persisted as a host plan file.

## Guest kernel and images

[pins.mk](pins.mk) records source URLs and SHA-256 hashes for the kernel,
Alpine and filesystem tools. The kernel combines
[kernel/terra.config](kernel/terra.config) with the architecture seed using
`allnoconfig`; `scripts/check-kernel-config.py` checks the resolved result.
Boot drivers are built in. The boot volume contains the agent and resize helper;
Terra does not ship a general-purpose module tree. Packages requiring other
kernel drivers need a built-in equivalent.

The pinned [kernel container](kernel/Containerfile) supplies the build tools and
the AArch64 compiler, native on AArch64 hosts and cross on x86_64. Its wrapper
mounts the repository read-only and `build/` writable, and disables network
access during compilation.

```sh
make kernel
make kernel-export
# Import an architecture-matched archive after verifying its source/provenance:
make KERNEL_ARCHIVE=/path/to/terra-kernel-x86_64.tar.gz KERNEL_ARCHIVE_SHA256=... kernel
```

Exports contain the compressed kernel, resolved configuration and input digest;
the companion `.sha256` records the archive checksum. The
[kernel workflow](.github/workflows/kernel.yml) exports both architectures.
Cross-compilation does not establish hardware boot acceptance.

Root and volume images are prebaked ext4 files. Creating a box decompresses
and sizes those images; the guest grows the filesystems. Runtime hosts need no
filesystem formatting tools or image downloads. The kernel and boot disk are
embedded in `terra` and decompressed directly into memory on each boot. The
read-only boot filesystem has no journal.
Each boot selects the payloads bundled with the binary starting the box, so
upgrading Terra and stopping/starting an existing box updates its kernel and
boot disk without rebuilding its root filesystem.

Guest RAM is demand-backed and Linux reports free pages through the memory
component for native discard. Guest capacity stays fixed; host RSS includes
runtime overhead and reclaim is asynchronous. The kernel command line uses
`init_on_alloc=1 init_on_free=1`: allocation and free-time clearing remain
enabled. See [usage](docs/usage.md) and
[security](docs/security.md) for the user contract and isolation limits.

Guest ext4 images are not byte reproducible: filesystem UUIDs, timestamps, and
compression metadata vary between builds. Pinned APK URLs can disappear from
Alpine's rolling package repositories; retain verified build downloads when
rebuilding historical releases.

## Verification

Build CI runs `verify-source → guest-assets → native host builds`. The first gate
checks formatting, WIT links, tool pins, and build scripts without guest images;
Rust/component tests run in the host jobs against the staged guest assets.
Build runs on pull requests and `main`; `v*` tags trigger releases for every
platform. Release reuses the Build workflow, adds source archives, then publishes
only after every build and check passes. Security audits run on dependency changes and weekly. Kernel changes
run tooling checks; kernel archive export is available through manual dispatch.

Two weekly workflows open pin-update PRs: `Guest pins bump` checks same-series
kernel LTS patches, stable e2fsprogs releases, and Alpine releases with doas and
its shim for both guest architectures. `Build tools bump` checks Rust stable
and nightly, Zig, Cargo build tools, container digests, abuild, and Debian
snapshot timestamps. Cargo dependencies and GitHub Actions remain covered by
Dependabot. Kernel LTS-series changes stay manual.

The updaters download guest artifacts before recording their SHA-256 hashes;
Alpine rootfs and e2fsprogs downloads are checked against upstream checksums.
Alpine and its packages move together, and mismatched architecture versions
stop the update. Tool updates keep build entry points synchronized and refresh
wit-bindgen lockfiles. Generated PRs require review; they are opened with the
`WORKFLOW_TOKEN` repository secret (fine-grained PAT with Contents, Pull
requests, Workflows, and Actions write) because `GITHUB_TOKEN` cannot push
workflow-file changes or open PRs, falling back to `GITHUB_TOKEN` when the
secret is unset. The jobs explicitly dispatch Build because PRs opened with
`GITHUB_TOKEN` do not trigger pull-request CI.

Preview updates without modifying files:

```sh
python3 scripts/update-pins.py alpine --dry-run
python3 scripts/update-pins.py e2fsprogs --dry-run
python3 scripts/update-build-tools.py rust --dry-run
python3 scripts/update-build-tools.py cargo-tools --dry-run
python3 scripts/update-build-tools.py zig --dry-run
python3 scripts/update-build-tools.py containers --dry-run
```

The [Linux amd64 acceptance report](docs/linux-amd64-acceptance.md) records the
tested artifact, host, commands, and results for the 2026-09-13 review.

```sh
make verify                 # component builds/tests, kernel-tool tests, fmt, Clippy, rustdoc, workspace tests
make verify KEEP_GOING=1    # run all independent checks and test suites, then report failure (CI mode)
make man                    # generated man pages
```

[crates/terra/src/cli.rs](crates/terra/src/cli.rs) is the source of truth for
CLI help, man pages and completions (`terra completions <shell>`). Generated man
pages are not committed.
After build assets exist, the native Rust fast path is:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
make verify-platform        # platform tests independently of runtime
make verify-dependency-boundaries
```

`verify-dependency-boundaries` reads the supported-target Cargo metadata graphs
and rejects platform paths to runtime, Wasmtime, WASI, or the guest protocol.
Tokio is a required dependency of platform and runtime; synchronous platform
APIs remain usable without starting a Tokio runtime. CI also cross-checks
platform for Windows; native VM gates remain required for execution behavior.

Windows tests run symlink fixtures by default. Enable Developer Mode or grant
the account permission to create symbolic links before running the suite.

Real Linux guest gates require `/dev/kvm`:

```sh
make dist
make test-component-boot
make test-platform-native-vm
make test-component-vmm
```

These exercise runtime/device integration, CLI boots, mounts, networking,
capacity and memory growth/reclamation. Ignored tests are not covered by an
ordinary workspace test pass. CI runs Linux VM gates when KVM is available;
see the [build workflow](.github/workflows/build.yml) for exact conditions.

`make test-platform-native-vm` checks preparation cleanup and repeated stop/join
on a native hypervisor without guest artifacts. On Apple Silicon the target
signs the test executable with the hypervisor entitlement before running it.

macOS and Windows have an opt-in `native_vm_tests` workflow input. After a native
host build (and signing on macOS), install Zig 0.16.0 for the guest probes and run:

```sh
TERRA_BIN="$PWD/dist/terra" cargo test --locked -p terra --test native_boot --test boot --test memory -- --ignored --test-threads=1 --nocapture
```

On Windows PowerShell:

```powershell
$env:TERRA_BIN = (Resolve-Path ./dist/terra.exe).Path
cargo test --locked -p terra --test native_boot --test boot --test memory -- --ignored --test-threads=1 --nocapture
```

Those gates cover guest CPUs, hooks, writable/read-only mounts, granted networking,
volume persistence, and rootless Podman image import/run/stop on a private disk.
The Podman gate downloads Alpine packages during setup and needs public egress. Native adapter code and a cross-target check alone do
not establish guest acceptance; outstanding host validation is in [todo.md](docs/todo.md).

Network policy coverage and boundary fuzzing use the existing tools:

```sh
python3 scripts/coverage-network-policy.py
cargo +nightly-2026-09-16 fuzz run network_policy -- -max_total_time=60 -max_len=4096
cargo +nightly-2026-09-16 fuzz run native_memory -- -max_total_time=60 -max_len=32768
```

Coverage requires matching LLVM tools (`LLVM_COV` and `LLVM_PROFDATA` can override
the paths); fuzzing requires cargo-fuzz. Coverage measures the policy component's
native Rust logic, and native sanitizers do not instrument AOT Wasm. Preserve
minimized findings in `fuzz/corpus/` and add regressions for the violated property.

## Component toolchain

Runtime versions are pinned in [terra-runtime/Cargo.toml](crates/terra-runtime/Cargo.toml),
component bindings in the component manifests, and component build commands in
[Makefile](Makefile). Vendored [WASI interfaces](components/wit/wasi/README.md)
are version 0.3.1. The `wasi_version` runtime integration test checks the actual
filesystem component's imports and linkage; update that test, the WIT and host
bindings together when changing runtime versions.

Production shared memory is disabled. `make verify` also runs the feature-gated
`shared_component_memory` and `shared_worker_memory` experiments. Those probes
exercise core-Wasm sharing and component API limitations; they do not establish
a supported transport between the generated device components.

## Performance tools

Keep comparison binaries outside version control and record their hashes with
results. Existing Linux/KVM tools provide repeatable comparisons:

```sh
python3 scripts/bench-vmm.py --legacy /path/to/baseline --component dist/terra --output build/vmm-comparison.json
python3 scripts/bench-shared-irqs.py --baseline /path/to/baseline --candidate dist/terra --output build/irq-comparison.json
```

Use `--help` for repetitions and workloads. The VMM tool measures readiness,
CPU/block/mount workloads, sampled RSS, idle CPU and terminal round trips; the
IRQ tool exercises shared mount/volume interrupt pools. Historical snapshots
and test counts are available in Git history rather than maintained as current
performance claims.

## Release source archives

`make source-dist` packages the committed checkout, pinned Linux and e2fsprogs
sources, and the Alpine package recipes, patches and upstream sources used by
the guest image. Source collection needs network access and Podman; `abuild`
checks downloads against the checksums in each pinned APKBUILD.

Releases publish `terra-source.tar.gz` beside the binaries. The ARM64 guest
job also publishes `terra-alpine-aarch64-source.tar.gz` from its own package
inventory. Each Alpine source archive includes the installed-package database
and a manifest recording source origins and aports commits.

## Troubleshooting

- **musl C compiler not found:** put Zig on `PATH`; `scripts/zig-musl-*` supplies the toolchain.
- **kernel build fails:** check unprivileged Podman, then rerun `make kernel`. Fix pin/configuration mismatches before retrying an import.
- **image build fails at `unshare`:** check the host's unprivileged-user-namespace policy. Images must be built with correct root ownership.
- **guest network is blocked:** inspect `terra logs`, adjust recipe `allow:` rules or network mode, then run `terra setup` to pin the change.
