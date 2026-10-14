# macOS sandboxing

Each worker runs as its own App Sandbox executable; the supervisor stays outside
App Sandbox. [Host process sandboxing](sandboxing.md) covers what each role
holds.

## Process layout

```text
terra (CLI)                 your user, unconfined
└─ terra __supervisor       outside App Sandbox; prebinds the agent,
   │                        stop and published listeners
   ├─ Worker.app … __vm     App Sandbox, signed copy of terra;
   │                        Hypervisor.framework, granted files and
   │                        shares; no network entitlement
   └─ Worker.app … __network
                            App Sandbox, signed copy of terra;
                            network connections, resolver files;
                            no hypervisor, disks or shares

__vm ◄── socket pair ──► __network
__supervisor ── startup channel ──► __network
__supervisor ── agent and stop listeners, run lock ──► __vm
terra (CLI) ── agent and control sockets ──► __vm
```

## Entitlements

| Worker | Entitlements |
| --- | --- |
| VM | Hypervisor.framework, approved VM files and shares, inherited IPC; no network client or server entitlement |
| Broker | Outgoing and incoming connections, resolver files, inherited IPC; no hypervisor, disks or shares |

The broker keeps the incoming-connections entitlement to accept on its
handed-over listeners, so App Sandbox alone does not stop it from listening.

## Signing

Each launch copies the executable into a private `.app` bundle under
`~/.terra`, writes role entitlements and signs it with `/usr/bin/codesign`. The
bundle identifier hashes the executable and grants, so differing roles and grants
never share an App Sandbox container. Signatures are ad hoc by default; set
`TERRA_MACOS_SIGN_IDENTITY` to use a keychain identity. Signing failure stops
startup. Developer ID signing and notarization of the shipped CLI are separate
distribution steps. Hardened Runtime is on for both roles; only the VM gets the
unsigned executable-memory exception that Wasmtime's AOT code loading needs.

## Activation check

Before initializing, each worker must fail to open a private
canary file outside its grants, and the VM must fail IPv4 and IPv6 loopback TCP
connects and listens. Any other outcome fails startup and reaps the worker;
entitlement presence alone is not trusted.

## Files

Grants use absolute-path file exceptions, which are additive: a
read-only grant inside a writable grant is rejected, since App Sandbox cannot
express a nested read-only bind. The VM gets the box directory read-only plus
specific writable disk, diagnostics and `runtime-logs/` paths. File exceptions
do not grant Unix-socket authority, so the supervisor prebinds the agent and stop
listeners and passes them to the VM as descriptors.

## Limits

App Sandbox keeps a platform baseline (system resources, world-readable
files, its container, temporary storage). There are no namespaces, seccomp or
mount remapping.

## Validation

Native acceptance on Apple Silicon macOS 15+:

```sh
cargo test -p terra-sandbox --lib macos -- --ignored --test-threads=1
```

Then run the packaged VM tests and exercise guest TCP, UDP, DNS, published
listeners, shares, stop, detached lifetime and abrupt supervisor or broker death.
