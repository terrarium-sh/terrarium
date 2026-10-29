# Terrarium development

Users start at the [README](README.md). Outstanding implementation and validation
work lives in [todo.md](docs/todo.md).
The guest network uses [per-socket TCP and UDP vsock streams](#network-transport).
Native validation on hosts other than Linux x86_64 remains pending.

## Build

Linux builds need Rust (pinned by [rust-toolchain.toml](rust-toolchain.toml)),
Podman for kernel compilation, Zig for the musl C toolchain, Make, Python 3,
`curl`, `tar`, `gzip`, and `unshare`. Building guest filesystem images requires
working unprivileged user namespaces. Running Linux guests requires readable
and writable `/dev/kvm`.

Install the separate component toolchain and validator:

```sh
git submodule update --init --recursive
rustup toolchain install nightly-2026-10-26 --component rustfmt,clippy --target wasm32-unknown-unknown
cargo install wasm-tools --version 1.262.0 --locked --target "$(rustc -vV | sed -n 's/^host: //p')"
make dist
```

`make dist` produces `dist/terra` with embedded guest images and trusted,
precompiled Wasmtime components and, on Linux, Bubblewrap, plus license notices.
Linux releases target static musl; ordinary Cargo commands use the native host
target. Production loads embedded AOT components without a Wasm compiler. Run
image-building Make targets sequentially in a shared checkout.
A musl build of a target with a checked-in policy compiles in the per-role
syscall and ioctl allowlists; see [host sandbox policy](docs/sandbox-policy.md).

The guest is Alpine Linux on the host's CPU architecture. Guest images are
built on Linux; macOS and Windows builds consume those images and compile AOT
components for their own host target. See [native host builds](packaging/README.md#native-host-builds)
for the Windows build command, Linux asset staging, platform requirements, and
signing. Windows builds use PowerShell and require a checkout with the shared
WIT [interface symlinks](components/wit/README.md) materialized correctly.

## Acceptance gates

The acceptance suite boots throwaway boxes and runs every user-facing feature
through the `terra` CLI. It needs only `terra`, `curl`, `tar` and access to the
Alpine package mirror (the podman step installs podman), takes a few minutes,
and leaves existing boxes alone. Each one-liner downloads the suite, so you can
run it on any test machine without a checkout.

A development build reports its version as `dev+<hash>`. Run it against the
suite from the branch it was built from. Replace `main` with your branch and
`./terra` with the binary to test:

```sh
curl -fsSL https://codeload.github.com/terrarium-sh/terrarium/tar.gz/main | tar -xz --strip-components=1 terrarium-main/acceptance && sh acceptance/run.sh --terra ./terra
```

```powershell
Invoke-WebRequest -UseBasicParsing https://codeload.github.com/terrarium-sh/terrarium/zip/main -OutFile terra-src.zip; if ($?) { Expand-Archive terra-src.zip -Force; powershell -ExecutionPolicy Bypass -File terra-src/terrarium-main/acceptance/run.ps1 -Terra .\terra.exe }
```

A release build is checked against its own release. Each release publishes the
runners as `terra-acceptance.sh` and `terra-acceptance.ps1`. Run on its own, a
runner downloads the suite of the version `terra` reports, checks it against
that release's `SHA256SUMS`, and runs it:

```sh
v=$(./terra --version | cut -d' ' -f2 | cut -d+ -f1) && curl -fsSL "https://github.com/terrarium-sh/terrarium/releases/download/v$v/terra-acceptance.sh" -o terra-acceptance.sh && sh terra-acceptance.sh --terra ./terra
```

```powershell
$v = ((.\terra.exe --version) -split ' ')[1] -replace '\+.*'; curl.exe -fsSL "https://github.com/terrarium-sh/terrarium/releases/download/v$v/terra-acceptance.ps1" -o terra-acceptance.ps1; if ($LASTEXITCODE -eq 0) { powershell -ExecutionPolicy Bypass -File terra-acceptance.ps1 -Terra .\terra.exe }
```

Or download `terra-acceptance.tar.gz` from the release page, extract it, and run
its `run.sh --terra ./terra` or `run.ps1 -Terra .\terra.exe`.

From a checkout, run `make dist && sh acceptance/run.sh --terra dist/terra` (on
Windows: `powershell -File acceptance/run.ps1 -Terra dist/terra.exe`). The
runner prints a timed summary of all steps. When a step fails, the runner prints
that step's log and keeps its working directory under `/tmp/terra-acceptance.*`.
A new user-facing feature gets a step in both `run.sh` and `run.ps1`.

## Code layout

| Path | Responsibility |
| --- | --- |
| `crates/terra` | CLI, recipes and manifests, box storage, VM launch and clients |
| `crates/terra-agent` | Linux guest initialization, hooks, workload and interactive services |
| `crates/terra-protocol` | Shared guest wire protocol |
| `crates/terra-policy` | Shared network policy rules and address decisions |
| `crates/terra-network` | Host network broker and its IPC client |
| `crates/terra-limits` | Shared resource limits |
| `crates/terra-hypervisor` | Native VMs, vCPU threads and guest memory over KVM, Hypervisor.framework and WHP |
| `crates/terra-platform` | Host filesystem, local-socket and child-process APIs |
| `crates/terra-sandbox` | Host confinement of VM and broker workers: Bubblewrap and seccomp, macOS Seatbelt profiles, Windows Less-Privileged AppContainers and jobs |
| `crates/terra-build` | Build-script logic: seccomp role filters and allowlist compiler, policy file format, Bubblewrap asset lookup, version string |
| `crates/terra-runtime` | Wasmtime stores, guest layout, scoped host capabilities, network configuration and policy contracts, and component/VM lifecycle orchestration |
| `components` | Wasm devices and services, reusable transport code, and shared WIT interfaces |
| `kernel`, `pins.mk` | Guest kernel configuration, integration patches, owned source overlay and pinned inputs |
| `fuzz` | Boundary fuzz targets and corpus |
| `scripts` | Build checks, benchmarks and pin maintenance |
| `packaging` | Host packages, service unit and bundled licenses |
| `web` | Project website |

Host confinement lives in `crates/terra-sandbox`, with one module per platform;
every launch is confined, with each role's built-in policy. VM launch planning
supplies explicit filesystem grants and environment values; the common
prepared-launch API owns platform dispatch, descriptors, and host-PID handoff.
`crates/terra-sandbox/src/linux/generator` (the `seccomp-policy` tool behind
`make policy`) derives the Linux syscall allowlists from per-role binaries,
built from `crates/terra/examples/role-*.rs`, which call the same
`terra::role` entry points as production.

Runtime derives the fixed machine layout and asks platform to create the VM,
RAM, disks and vCPUs. A short-lived boot component plans kernel placement;
runtime validates its writes and result before CPUs start. The VMM component
then owns exit interpretation and lifecycle decisions. Native MMIO routing connects
device components through bounded request/reply streams. Software interrupt
emulation runs in its own store with no imported host functions. Hypervisor
operations and authority checks remain native. See the
[security model](docs/security.md) for trust boundaries and resource limits.

`components/vsock-frontend` owns one stock virtio-vsock device, using
`components/vsock-device` for packet/credit mechanics; see
[network transport](#network-transport). One fixed bounded pipe connects the
frontend to `components/agent` in a separate store. The frontend receives guest
RAM, its IRQ and broker imports; the agent receives authorized service streams
without RAM, IRQ or broker imports.

Runtime entry points live in `terra-runtime::orchestration`; `machine` owns
layout, validated machine configuration, and conversion to native VM configuration.
A prepared VM runs through `PreparedVm::run`, which keeps its component runtime
and outcome observer paired. `box_runtime/setup.rs` owns device preparation and
startup sequencing. `component/vmm.rs` initializes the VMM; `component/mmio.rs` owns routing and device
streams, and `component/interrupt_controller.rs` validates interrupt effects before
native injection. `component/vmm/vcpu.rs` hosts the vCPU rendezvous.
Device module roots own registration and selected public exports; private
`bindings.rs` files hold generated interfaces, and `host.rs` implements native imports.
Network socket authorization lives in `crates/terra-network/src/server.rs`;
`crates/terra-policy` validates network policy natively in the CLI and broker.

Shutdown responsibilities stay with their resource owners:

| Owner | Responsibility |
| --- | --- |
| `orchestration/observation.rs` | Observe the VM outcome and await final cleanup |
| `component/vmm/lifecycle.rs` | Publish events and outcomes and establish the shared shutdown deadline |
| `box_runtime` | Stop and join Wasmtime tasks |
| `component/vmm/teardown.rs` | Sequence native cleanup and retain resources when cleanup cannot finish |
| `component/vmm/native_task.rs` | Run cleanup independently of cancellation of a waiter |
| `terra-hypervisor` `vcpus.rs` | Stop and join native vCPU threads |

The agent starts as PID 1 from the read-only 3 MiB memory-backed boot disk,
receives its boot plan over the fixed agent vsock stream and enters the Alpine
root with `pivot_root`. Setup's VM grows the root filesystem, runs `on_create`
when its commands differ from the guest-side stamp, and creates the recipe's
directories. Run boots grow volume filesystems to their images, mount shares
and volumes, then run hooks and the workload. Boot-plan environment values are
sent through memory, not persisted as a host plan file.

## Network transport

External guest sockets never touch host networking directly. The guest kernel
code (`kernel/overlay/net/terra/`) and its upstream integration patch
(`kernel/patches/0004-terra-socket-vsock.patch`) redirect each external
TCP or UDP socket to its own vsock stream; guest-local addresses, loopback,
namespaces and bridges stay on ordinary Linux networking. The frontend relays
each stream to the restricted broker, which authorizes every destination.

| Stream | Opened by | Guest port | Host port |
| --- | --- | --- | --- |
| Agent | Guest agent | 6000 | 6000 |
| Network control (readiness, DNS) | Guest agent, userspace AF_VSOCK | 6001 | 6001 |
| One per external TCP socket | Guest kernel | any other | 6002 |
| One per external UDP socket | Guest kernel | any other | 6003 |
| One per published TCP connection or UDP listener | Frontend | 6004 | `0x100000..0x200000` |

One virtio-vsock device carries everything (guest CID 3, host CID 2). TCP, UDP
and publication streams share a 1024-stream admission limit; the agent and control
streams are reserved separately. Any guest process can reach ports 6001–6003, so
a port never selects a host capability. Local-only mode
(`network.enabled: false`) admits only the agent stream and runs no broker.

Frames are an 8-byte header (opcode, reserved, payload length) plus payload; the
opcodes, endpoint encoding and error codes are defined in
`crates/terra-protocol/src/application.rs` and `socket.rs`, and the
broker IPC in `network.rs`. The kernel, agent, components and runtime must be
built together: every opening frame carries the network ABI version, and
packaged kernel and boot images carry ABI markers checked before boot.
`scripts/kernel/check-vsock-abi.py` checks the kernel overlay against the Rust constants.

- **TCP:** the guest sends TcpOpen; the frontend connects through the broker and
  answers TcpOpened before guest `connect` returns. After that the stream carries
  raw bytes, and stock vsock provides backpressure and half-close. Accepted bytes
  drain through every queue before FIN. Opening errors are precise; afterwards a
  reset is `ECONNRESET` and EOF is EOF. The opening deadline is 30 seconds.
- **UDP:** the first external use opens the stream (the only synchronous round
  trip); `sendto` then returns once the datagram is queued. Denied or failed sends
  come back as UdpError, which sets the socket's asynchronous error and, with
  `IP_RECVERR`, an error-queue entry. `connect` is guest-local filtering. The
  broker accepts inbound datagrams only from the 128 most recent peers the socket
  sent to within 60 seconds. Frontend and broker exchange ordered batches of up to
  64 datagrams per IPC frame (broker protocol 1).
- **QUIC compatibility:** external UDP accepts the options QUIC stacks set, as
  documented no-ops where the host cannot honor them: DF/MTU discovery
  (`IP_MTU_DISCOVER`, `IPV6_DONTFRAG`), ECN (`IP_RECVTOS`, `IP_TOS` and their IPv6
  forms, with markings dropped) and `SO_BROADCAST`. Each datagram carries at
  most 4096 bytes. `UDP_SEGMENT` (GSO) sends up to 64 such segments in one
  atomic run; a run larger than the carrier's credit returns `EMSGSIZE`.
  `UDP_GRO` coalesces received runs and reports their segment size. `sendmsg` accepts ECN, `UDP_SEGMENT` and same-source
  `PKTINFO` control messages; others return `EOPNOTSUPP`. With DF a no-op, the
  host may fragment a PMTU probe, so QUIC can choose a larger MTU than the path's.
- **Control:** the agent sends Hello and waits for Ready before configuring DNS.
  It serves DNS at `100.96.0.53:53` and forwards queries (16 in flight) over this
  stream for broker resolution. Losing the control stream retires all network
  streams; agent control continues.
- **Publication:** only trusted configuration creates host loopback listeners (at
  most 32 mappings); the supervisor binds them and hands them to the broker,
  which cannot listen itself. The frontend opens a stream to guest port 6004 per accepted
  TCP connection, or one per UDP listener family, and sends a header naming the
  configured guest port. The agent checks it against the boot plan and relays to
  the service from source `169.254.96.1`, delivering to `100.96.0.2:<port>`.

Queued-payload budgets per stream:

| Stream | Upstream | Replies |
| --- | ---: | ---: |
| Agent | 64 KiB | 256 KiB |
| Control | 32 KiB | 128 KiB |
| Each TCP/UDP/publication stream | 64 KiB | 80 KiB |

The 1024 flows' allowances total 144 MiB inside the frontend's 216-MiB Wasm
memory floor, which applies whatever `components.memory_mib` says.
Local-only boxes use the ordinary component limit. Guest UDP sockets keep a 64-KiB carrier window and a decoded queue
of at most 48 datagrams. VM process and broker share one yamux connection, which
grants each stream a 256 KiB receive window, so 1024 flows can queue about 256 MiB
in each direction. The broker admits 2048 resources and 16 DNS lookups at once,
and raises its open-file soft limit to fit them. These are admission bounds,
not resident-memory measurements.

## Boot readiness and failures

The guest boot deadline is 60 seconds (`terra_runtime::orchestration::GUEST_BOOT_TIMEOUT`),
starting when guest execution starts. The agent sends `AgentReady` after
initialization and before hooks. Readiness permanently cancels this deadline;
long hooks keep their existing limits. `--agent-timeout` separately bounds a
client's connection wait.

Detached startup waits for the VM child's readiness notification. Its parent
wait is bounded to 90 seconds: the guest deadline plus 30 seconds for preparation
and cleanup. If the child never responds, the parent kills it and waits at most
2 seconds for reaping. An uninterruptible child cannot hold the CLI indefinitely;
the CLI reports a cleanup failure if the child still cannot exit. A child that exits before
readiness retains its nonzero exit code, including `128 + signal` on Unix.

Boot failures replay bounded host and guest log tails, explicitly noting empty
guest diagnostics. Native KVM failures include the vCPU and operation or hardware
exit reason, even if the guest agent never runs.

`host.pid` in the box directory holds the VM's host PID and start identity for
stop and liveness checks; the supervisor writes it, and the sandboxed VM sees it
read-only.

## Shared mounts

Each mount runs up to 32 filesystem requests at once and queues up to 256,
counting reads, writes, flushes and metadata calls individually; requests on
one file run in order. Event resolution keeps one reserved slot, and
cancellation bypasses the queue through reserved virtio-fs ring capacity. Each
mount has its own runtime with at most 33 blocking threads, so a stalled mount
does not starve other mounts or disks. Descriptor cleanup runs off the worker
and holds its reservation until it finishes; teardown waits at most one second
for remaining tasks.

Host edits do not invalidate pages the guest has mapped. On macOS, objects the
guest cannot read are tracked by a parent-relative reference; a host rename or
delete makes it return not-found until the guest looks it up again.

## Sync

Sync compares modification times at microsecond precision. Before a download,
it creates temporary name-only entries in the destination to find collisions
between incoming and existing names and to resolve aliases in symlink chains;
missing directories are modeled under their nearest existing ancestor. Probes
are removed and parent modification times restored before transfers begin, but
file events and change times can still show them. Directories whose comparison
settings the probes would not inherit are refused. Windows refuses names and
link targets containing `~` because DOS short-name aliases cannot be reproduced
in a temporary directory.

## Guest kernel and images

[pins.mk](pins.mk) records source URLs and SHA-256 hashes for the kernel,
Alpine and filesystem tools. The kernel combines
[kernel/terra.config](kernel/terra.config) with the architecture seed using
`allnoconfig`; `scripts/kernel/check-kernel-config.py` checks the resolved result.
Boot drivers are built in. The boot volume contains the agent and resize helper;
Terra does not ship a general-purpose module tree. Packages requiring other
kernel drivers need a built-in equivalent.

Kernel and boot gzip assets include [trusted ABI markers](#network-transport).
Terra embeds them repacked as chunked LZ4 (`.tlz4`): independently compressed
LZ4-HC chunks, each with a CRC32, behind a header that carries the same marker.
The kernel uses 1 MiB chunks and is streamed into guest RAM at boot. The boot
disk uses 64 KiB chunks and is read in place, decoding only the chunks the
guest touches. Markers are checked before any decompression and VM creation.
Make targets package both forms automatically. To package verified matching raw
images manually, select the image kind as the first positional argument:

```sh
cargo run --locked -p terra-protocol --example package-guest-image -- kernel build/vmlinux build/vmlinux.gz
cargo run --locked -p terra-protocol --example package-guest-image -- boot build/boot.img build/boot.img.gz
cargo run --locked -p terra-protocol --features packer --example repack-guest-image -- kernel build/vmlinux.gz build/vmlinux.tlz4
cargo run --locked -p terra-protocol --features packer --example repack-guest-image -- boot build/boot.img.gz build/boot.img.tlz4
```

The kernel's 12-byte standard gzip `TK` subfield records `VS` and little-endian
socket/application/vsock ABI versions. The boot image uses its separate `TB`
marker. Direct `VmInput` callers supplying their own images are responsible for
matching their trusted artifacts; the live version handshake still runs.

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

The x86 timer patch lets virtual guests calibrate the local APIC timer against
a known TSC frequency when the APIC timer is always running, avoiding a PIT
clockevent whose IRQ can register without a timer behind it. The existing
fallback for failed legacy IRQ registration remains for WHP. The ignored
`local_apic_timers_work_without_a_legacy_clockevent` boot test checks one and two
vCPUs for active local timers and no IRQ 0 clockevent on x86 KVM; Intel acceptance
still requires running it on the affected host.

Root and volume images are prebaked ext4 files. Setup decompresses and sizes
the root and box-lifetime images; run boots recreate boot-lifetime images.
The guest grows the root filesystem during setup and volume filesystems on
every boot. Runtime hosts need no filesystem formatting tools or image downloads.
The kernel and boot disk are embedded in `terra` as chunked LZ4 containers:
each boot decodes the kernel into guest memory, while the boot disk stays packed
and the block device decodes only the chunks a read touches. The read-only boot
filesystem has no journal.
Each boot selects the payloads bundled with the binary starting the box, so
upgrading Terra and stopping/starting an existing box updates its kernel and
boot disk without rebuilding its root filesystem.

On x86_64, guest RAM skips the device region from 3.25 GiB to 4 GiB, where
virtio devices and interrupt controllers sit, and continues above 4 GiB.
`hw.mem_mib` counts mapped RAM only; Linux reserves some of it for boot data.
Guest RAM is demand-backed and Linux reports free pages through the memory
component for native discard. Guest capacity stays fixed; host RSS includes
runtime overhead and reclaim is asynchronous. The kernel command line uses
`init_on_alloc=1 init_on_free=0`: memory is cleared on allocation, avoiding
a full RAM clear during boot. Freed memory is cleared when reused rather than
immediately on release. See [usage](docs/usage.md) and
[security](docs/security.md) for the user contract and isolation limits.

Guest ext4 images are not byte reproducible: filesystem UUIDs, timestamps, and
compression metadata vary between builds. Pinned APK URLs can disappear from
Alpine's rolling package repositories; retain verified build downloads when
rebuilding historical releases.

## Verification

Real HTTP/3 tests and benchmarks use a static Rust quinn/h3 fixture
(`crates/terra/tests/assets/http3_probe`), with certificate verification and no
TCP fallback. After `make dist`, run `make test-http3` on native Linux/KVM. This checks GET/POST
compatibility and verified 1-MiB uploads/downloads on the host and inside a Terra box.
For throughput:

```sh
python3 scripts/bench/bench-http3.py --terra dist/terra --runs 5 --mib 64 --output build/http3-benchmark/report.json
```

The benchmark measures one HTTP/3 stream after warming its QUIC connection.
Uploads receive a small acknowledgment; downloads verify the response body.
Reports retain every sample, command output, fixture log and executable/source
hash. The native client uses the same UDP-only server. These loopback results
measure application throughput, not WAN performance. Keep the host otherwise
idle; `--probe` reuses an already built static fixture.

Build CI runs `verify-source → guest-assets → native host builds`. The first gate
checks formatting, WIT links, tool pins, and build scripts without guest images;
Rust/component tests run in the host jobs against the staged guest assets.
Build runs on pull requests and `main`; `v*` tags trigger releases for every
platform. Release reuses the Build workflow, adds source archives, then publishes
after required build and check jobs pass. Security audits run on dependency changes and weekly. Kernel changes
run tooling checks; kernel archive export is available through manual dispatch.

Each Linux build job runs `make policy-check`, which regenerates the seccomp
allowlists by statically scanning that architecture's role binaries and fails
when they differ from the checked-in policy. It needs no KVM. The KVM gates then
run the boot and guest suites against the distribution, whose compiled-in
allowlists kill any syscall the generator missed.

Releases build every platform but run VM gates on Linux amd64, plus any host
with a configured native runner. On the other hosts, run the
[acceptance suite](#acceptance-gates) that each release ships.

After a change that can alter the syscalls a sandboxed role makes, including
dependency and toolchain bumps, regenerate and review the policy:

```sh
make policy
make TERRA_TARGET=aarch64-unknown-linux-musl policy
git diff crates/terra-sandbox/src/linux/policy/
```

[Host sandbox policy](docs/sandbox-policy.md) explains the analysis and what makes
it refuse a site. New host operations also need boot-test coverage, which runs
under the allowlists, as [AGENTS.md](AGENTS.md) requires.

Two weekly workflows open pin-update PRs: `Guest pins bump` checks same-series
kernel LTS patches, stable e2fsprogs releases, and Alpine releases with doas and
its shim for both guest architectures. `Build tools bump` checks Rust stable
and nightly, Zig, Cargo build tools, container digests, abuild, and Debian
snapshot timestamps. Cargo dependencies and GitHub Actions remain covered by
Dependabot. Kernel LTS-series changes stay manual.

The updaters download guest artifacts before recording their SHA-256 hashes.
e2fsprogs tarballs and Alpine rootfs images are verified against PGP signatures
from the committed [.github/keys](.github/keys); Alpine indexes and packages are
verified against the committed Alpine repository keys and each package's
signed datahash. Alpine and its packages move together, and mismatched architecture
versions stop the update. Tool updates keep build entry points synchronized and
refresh wit-bindgen lockfiles. CI reads tool versions from the committed pins,
so generated PRs do not change workflow files. Generated PRs require review
and use `GITHUB_TOKEN`; enable **Settings → Actions → General → Workflow
permissions → Allow GitHub Actions to create and approve pull requests** for
PR creation. The jobs explicitly dispatch Build so token-created PRs receive
validation.

Preview updates without modifying files:

```sh
python3 scripts/pins/update-pins.py alpine --dry-run
python3 scripts/pins/update-pins.py e2fsprogs --dry-run
python3 scripts/pins/update-build-tools.py rust --dry-run
python3 scripts/pins/update-build-tools.py cargo-tools --dry-run
python3 scripts/pins/update-build-tools.py zig --dry-run
python3 scripts/pins/update-build-tools.py containers --dry-run
```

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
Guest symlinks in host shares are stored WSL-style rather than as Windows
symlinks, through the VM's wrapper when sandboxed; see
[Windows sandboxing](docs/sandboxing-windows.md).

Real Linux guest gates require `/dev/kvm`:

```sh
make dist
make test-component-boot
make test-platform-native-vm
make test-component-vmm
```

These exercise runtime/device integration, CLI boots, mounts, networking,
capacity and memory growth/reclamation. Ignored tests are not covered by an
ordinary workspace test pass.

CI runs the [acceptance gates](#acceptance-gates) against each platform's build.
The suite's guest-side checks in `acceptance/guest/` are shared with the `guest_suite`
cargo test. Releases ship the suite as `terra-acceptance.tar.gz` and the runners
as `terra-acceptance.sh` and `terra-acceptance.ps1`; a runner fetched on its own
downloads the suite of the installed release and hands over to that release's
runner. `scripts/checks/test-native-gates.py` keeps the two
runners' steps and guest scripts identical.

`make test-platform-native-vm` checks preparation cleanup and repeated stop/join
on a native hypervisor without guest artifacts. On Apple Silicon the target
signs the test executable with the hypervisor entitlement before running it.

Build and release CI require native platform, runtime, and packaged VM acceptance
on Linux amd64. ARM64 Linux, macOS and Windows VM gates are opt-in until native
runners are available. Set `native_vm_tests` to request those gates explicitly;
an explicitly requested gate fails when virtualization is unavailable. Configure
`LINUX_X64_VM_RUNNER`, `LINUX_ARM64_VM_RUNNER`, `MACOS_ARM64_VM_RUNNER`,
`WINDOWS_X64_VM_RUNNER`, and `WINDOWS_ARM64_VM_RUNNER` with native runner labels.
Linux needs read/write KVM and unprivileged user namespaces, macOS needs Apple
Silicon with Hypervisor.framework access, and Windows needs working WHP. Configured
native runners run the full gates automatically. Hosted builds on the other
platforms run compiler and unit checks and report missing boot coverage; the
[build workflow](.github/workflows/build.yml) has the exact conditions.
Hosted Linux jobs give the runner account ownership of an existing `/dev/kvm`
with mode `0600` and a persistent udev rule before VM and policy checks. A missing
device still fails required VM gates; self-hosted runners must configure their
own KVM permissions.

After a native host build (and signing on macOS), install Zig 0.17.0 for the guest
probes. Use a short temporary directory with enough disk space (`TMPDIR` on Unix,
`TEMP`/`TMP` on Windows); fixture control sockets must fit the local-socket path
limit. Run the packaged gates:

```sh
TMPDIR=/tmp TERRA_BIN="$PWD/dist/terra" cargo test --locked -p terra --test native_boot --test boot --test memory -- --ignored --test-threads=1 --nocapture
```

On Windows PowerShell:

```powershell
$env:TERRA_BIN = (Resolve-Path ./dist/terra.exe).Path
cargo test --locked -p terra --test native_boot --test boot --test memory -- --ignored --test-threads=1 --nocapture
```

The native file-events test can use `TERRA_FILE_EVENTS_PROBE` instead of Zig:
point it to a static Linux binary built from `crates/terra/tests/assets/file_events_probe.c`
for the guest architecture.

Those gates cover guest CPUs, hooks, writable/read-only mounts, granted networking,
volume persistence, and rootless Podman image import/run/stop on a private disk.
The Podman gate downloads Alpine packages during setup and needs public egress. Native adapter code and a cross-target check alone do
not establish guest acceptance; outstanding host validation is in [todo.md](docs/todo.md).

Network policy coverage and boundary fuzzing use the existing tools:

```sh
python3 scripts/checks/coverage-network-policy.py
cargo +nightly-2026-10-26 fuzz run network_policy -- -max_total_time=60 -max_len=4096
cargo +nightly-2026-10-26 fuzz run native_memory -- -max_total_time=60 -max_len=32768
```

Coverage requires matching LLVM tools (`LLVM_COV` and `LLVM_PROFDATA` can override
the paths); fuzzing requires cargo-fuzz. Coverage measures the native `terra-policy` logic, and native sanitizers do not instrument AOT Wasm. Preserve
minimized findings in `fuzz/corpus/` and add regressions for the violated property.

## Component toolchain

Runtime versions are pinned in [terra-runtime/Cargo.toml](crates/terra-runtime/Cargo.toml),
component bindings in the component manifests, and component build commands in
[Makefile](Makefile). Vendored [WASI interfaces](components/wit/wasi/README.md)
are version 0.3.1. The `wasi_version` runtime integration test checks the actual
filesystem component's imports and linkage; update that test, the WIT and host
bindings together when changing runtime versions.

## Performance tools

Keep comparison binaries outside version control and record their hashes with
results. Existing Linux/KVM tools provide repeatable comparisons:

```sh
python3 scripts/bench/bench-vmm.py --legacy /path/to/baseline --component dist/terra --output build/vmm-comparison.json
python3 scripts/bench/bench-network.py --terra dist/terra --output build/network-comparison.json
```

Use `--help` for repetitions and workloads. The VMM tool measures readiness,
CPU/block/mount workloads, sampled RSS, idle CPU and terminal round trips; the
network tool measures TCP and UDP throughput, latency and connection churn.
Historical snapshots and test counts are available in Git history rather than
maintained as current performance claims.

## Release source archives

`make source-dist` packages the committed checkout, the pinned Bubblewrap
submodule, Linux, e2fsprogs and libcap sources, and the Alpine package recipes,
patches and upstream sources used by the guest image. Source collection needs
network access and Podman; `abuild`
checks downloads against the checksums in each pinned APKBUILD.

Releases publish `terra-source.tar.gz` beside the binaries. The ARM64 guest
job also publishes `terra-alpine-aarch64-source.tar.gz` from its own package
inventory. Each Alpine source archive includes the installed-package database
and a manifest recording source origins and aports commits.

## Troubleshooting

- **musl C compiler not found:** put Zig on `PATH`; `scripts/toolchain/zig-musl-*` supplies the toolchain.
- **kernel build fails:** check unprivileged Podman, then rerun `make kernel`. Fix pin/configuration mismatches before retrying an import.
- **image build fails at `unshare`:** check the host's unprivileged-user-namespace policy. Images must be built with correct root ownership.
- **guest network is blocked:** inspect `terra logs`, adjust recipe `allow:` rules or network mode, then run `terra setup` to pin the change.
