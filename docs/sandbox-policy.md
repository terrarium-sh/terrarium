# Host sandbox policy

Terra always starts the VM and its network broker in its built-in native
sandbox: Bubblewrap on Linux, Seatbelt on macOS and AppContainer on Windows.
There is no unconfined or custom launcher, and nothing changes a policy at run
time: no setting, file or environment variable. A failed sandbox launch stops
the box without fallback. [Host process sandboxing](sandboxing.md) describes
each role and platform.

## Linux seccomp filters

Each Linux role runs under two stacked seccomp filters; a syscall must pass both:

1. A **role filter** denies dangerous kernel interfaces and alternate syscall
   ABIs and enforces argument rules: socket families, outgoing `sendto`, the
   parent-death signal, terminal-injection ioctls
   ([Linux sandboxing](sandboxing-linux.md)).
2. An **allowlist** of the syscalls, and `ioctl` requests, the role's code can
   make. Any other call kills the process.

Both are compiled into the executable. Bubblewrap installs a worker's role
filter before executing it; the worker installs its allowlist as it starts, and
the supervisor installs both once it has launched its workers. Every allowlist
also admits `restart_syscall`, which the kernel issues to resume an interrupted
sleep. The allowlists come from
`crates/terra-sandbox/src/linux/policy/<target>.json`, one file per static musl
target, generated from the code and checked in. A glibc development build has
no scannable libc and runs with the role filters alone; released binaries are
always static musl.

## How allowlists are generated

`make policy` builds one binary per sandboxed role (supervisor, VM worker,
network broker), each linking only the code that role can run, and scans its
machine code. Production runs every role through the same entry functions those
binaries call. For each `syscall` (x86-64) or `svc` (AArch64) instruction, the
generator works out the syscall number, and for `ioctl` the request, by tracing
the registers backward through the function, through jump tables, and into
every caller of wrappers such as musl's `syscall()` and `ioctl()`.

Nothing runs during generation, so it needs no KVM, `ptrace` or user namespaces,
and AArch64 policies can be generated from cross-compiled binaries. The result
covers every path the code can reach, not only the paths a test exercised.

The generator fails rather than guess. It refuses a site when:

- a syscall number or request comes from memory or arithmetic it does not follow;
- a function's control flow is not fully known: undecodable bytes, an
  unrecovered jump table, or another function jumping into its middle;
- a wrapper's address escapes to code it cannot follow, such as being stored,
  returned or passed to an unknown callee;
- syscall instruction bytes appear outside the analyzed code, or a legacy
  syscall entry (`int 0x80`, `sysenter`) is used;
- a binary registers constructors that would run outside the scanned code.

When it refuses, make the code analyzable; do not widen the policy by hand.

## Keeping policies current

Any change that can alter which syscalls a sandboxed role reaches, including
dependency and toolchain upgrades, needs regenerated policies:

```sh
make policy                                         # this host's target
make TERRA_TARGET=aarch64-unknown-linux-musl policy  # each Linux architecture
git diff crates/terra-sandbox/src/linux/policy/      # review, then commit
```

CI runs `make policy-check` in every Linux build job, without KVM, and fails on
any difference. KVM runners also run the boot suite under the compiled-in
allowlists, so a missed syscall kills a real VM before release.
