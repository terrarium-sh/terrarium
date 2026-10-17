# macOS sandboxing

Each worker runs under a Seatbelt profile that a trusted launcher applies before
the worker's code runs; the supervisor stays unconfined. [Host process
sandboxing](sandboxing.md) covers what each role holds.

## Process layout

```text
terra (CLI)                 your user, unconfined
└─ terra __supervisor       unconfined; prebinds the agent, stop and
   │                        published listeners
   ├─ __sandbox_launcher    trusted; applies the VM profile, then execs:
   │  └→ __vm               Hypervisor.framework, granted files and
   │                        shares; no network, no child processes
   └─ __sandbox_launcher    trusted; applies the broker profile, then execs:
      └→ __network          network connections, resolver files; no
                            disks, shares or child processes

└→ is an exec: the launcher becomes the worker and keeps its PID and descriptors.

__vm ◄── socket pair ──► __network
__supervisor ── startup channel ──► __network
__supervisor ── agent and stop listeners, run lock ──► __vm
terra (CLI) ── agent and control sockets ──► __vm
```

## Profiles

Every profile denies by default, imports Apple's `system.sb` baseline and is
built into terra. A role adds these rules to the shared base, which also lets
the worker exec its own executable.

| Worker | Allowed on top of the base |
| --- | --- |
| VM | Its granted files and shares, and the FSEvents daemon for share notifications; no network, no child processes |
| Broker | Name resolution through mDNSResponder, outbound connections to any IP (including host loopback), UDP binds and inbound UDP, socket creation, granted resolver files; no TCP binds, so it cannot open TCP listeners; no disks, shares or child processes |

The broker accepts on listeners the supervisor binds and hands over, which
needs no network rule.

## Launcher

The supervisor writes an owner-only spec (role, canonical grants) under
`~/.terra`. The launcher renders the profile with the executable and every
grant passed as parameters, so no path from the spec enters the profile text.
It applies the profile with `sandbox_init_with_parameters` and execs the
worker. There is no per-launch signing. The shipped executable is signed once
with Hardened Runtime and `packaging/macos.entitlements`, so both workers carry
the hypervisor and unsigned-executable-memory entitlements. Hypervisor.framework
is not gated by Seatbelt, so no profile keeps the broker from creating a VM.

## Activation check

Before initializing, each worker must fail to open a private canary file (the
launch spec) outside its grants, and the VM must fail IPv4 and IPv6 loopback
TCP connects and listens. Any other outcome fails startup and reaps the worker;
a successful profile call alone is not trusted.

## Files

Grants are profile rules on canonical paths: Seatbelt matches resolved paths, so
`/tmp` grants become `/private/tmp`. Each grant's ancestor directories also get
a metadata-only rule, because the file-events watcher canonicalizes each share
path. The VM can also send IPC to the FSEvents daemon, which that watcher
subscribes through; the daemon delivers only events for paths the VM's file
rules allow. A read-only grant inside a writable grant is still rejected; no
caller needs it. The VM gets the box directory read-only plus specific writable
disk, diagnostics and `runtime-logs/` paths. File rules do not grant Unix-socket
authority, so the supervisor prebinds the agent and stop listeners and passes
them to the VM as descriptors.

## Limits

- Both profiles include Apple's `system.sb` baseline. There are no namespaces,
  seccomp filters or mount remapping.
- The broker keeps outbound network access, including host loopback, and can
  reach mDNSResponder. It cannot bind TCP sockets, so it cannot open TCP
  listeners; UDP binds work.
- Both workers are the same signed binary and carry the hypervisor
  entitlement, and Seatbelt does not gate Hypervisor.framework, so a
  compromised broker could create a VM.
- Seatbelt's profile interface is private and deprecated, so a macOS update could
  change it.
- Boxes start over SSH: Seatbelt needs no GUI login session.

## Validation

Native acceptance on Apple Silicon macOS 15+, from an SSH session:

```sh
make TERRA_TARGET=aarch64-apple-darwin host-dist
codesign --force --sign - --options runtime --entitlements packaging/macos.entitlements dist/terra
TERRA_BIN=$PWD/dist/terra CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER="sh $PWD/scripts/toolchain/run-macos-vm-test" \
  cargo test -p terra-sandbox --lib macos -- --ignored --test-threads=1 --nocapture
```

Then run the packaged VM tests and exercise guest TCP, UDP, DNS, published
listeners, shares, stop, detached lifetime and abrupt supervisor or broker death.
