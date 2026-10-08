# Host VM launchers

Terra can start its host VM process directly, through a custom launcher, or
through its built-in native sandbox. Configure the choice globally in
`~/.terra/config.yaml`; a project recipe cannot change it. An absent or null
`vm.init` selects `bwrap`: Bubblewrap on Linux and native App Sandbox/AppContainer
launchers on macOS/Windows. The native launch separates the VM and network
broker and applies an independent policy to each. Linux also uses a supervisor
seccomp filter. A failed sandbox launch stops the box without automatic fallback.

Network-enabled launches use a supervised network broker; local-only launches
(`network.enabled: false`) omit it. [Host process sandboxing](sandboxing.md)
describes each role and platform.

```yaml
vm:
  init: direct
```

`vm.init: direct` opts out of the built-in process confinement for both the VM
and its broker. On Linux,
Terra embeds Bubblewrap and separate fallback filters for the supervisor, VM,
and network broker. Select a generated policy bundle with:

```yaml
vm:
  init: bwrap
  bwrap:
    policy: /path/to/terra-seccomp
```

Policy selection has three steps:

1. Use `vm.bwrap.policy` when set. Relative paths resolve against the directory
   containing `config.yaml`.
2. Otherwise use `~/.terra/config/seccomp` if present; `install.sh` installs
   the release bundle there.
3. Otherwise use the built-in role policies.

A bundle contains `manifest.json` and separate `supervisor.seccomp.bpf`,
`vm.seccomp.bpf`, and `network.seccomp.bpf` files. Generated bundles also include
readable JSON for each filter. Terra checks the version, target, per-role hashes,
filter sizes, and instruction alignment; the kernel validates installation.
Missing or invalid selected bundles fail startup without fallback.

Legacy single-policy files, including `~/.terra/config/seccomp.bpf`, are rejected.
To migrate, run `terra self-test --generate-policy`, then select the resulting
bundle directory. Regenerate after changing Terra and validate on the intended
host architecture. Terra never downloads a policy or searches beside its binary.

The built-in filters deny dangerous kernel interfaces and alternate syscall
ABIs and keep each role's socket limits ([Linux sandboxing](sandboxing.md#linux));
generated bundles add tighter syscall and ioctl allowlists. A permanent role
filter stays active alongside a selected bundle, so a permissive custom bundle
cannot lift the socket and parent-death restrictions.

To require a generated bundle, set:

```yaml
vm:
  init: bwrap
  bwrap:
    allow_fallback: false
```

`allow_fallback` defaults to `true`. With `false`, an explicit bundle or
`~/.terra/config/seccomp` must exist. This setting does not assess how restrictive
the selected filters are. Normal boots do not need a policy compiler.

Bubblewrap settings are unused when `vm.init` selects another launcher.
Terra refuses a configured launcher or selected local policy inside a
guest-writable share or writable Terra box state, so a guest cannot replace
an asset used for a later boot.

## Generate a policy from the installed binary

`terra self-test` exercises the embedded host components without starting a VM,
tracing, or generating a policy. The host checks cover block storage, shared files
and host file-change notifications, memory, networking, agent streams, and device lifecycle.
`terra self-test --validate-vm` also runs the bundled guest suite using the normal
platform launcher and policy settings. Windows host filesystem checks require
Developer Mode or permission to create symbolic links.

On Linux, `--generate-policy` traces the selected checks, compiles a syscall/ioctl
allowlist for each process role, and repeats the host checks under the complete
generated bundle. Reviewed
supplements cover virtualization operations that cannot be observed without a
hypervisor. Terra embeds the guest suite and syscall tracer, uses the Rust
`seccompiler` crate to compile classic BPF, and resolves syscall names with the
Rust `syscalls` crate.
Host checks and their policy generation need no source checkout, Rust toolchain,
Python, `strace`, libseccomp, or `/dev/kvm`. The Linux tracer uses `ptrace`, so the
host must permit tracing Terra child processes.

```sh
terra self-test
terra self-test --validate-vm
terra self-test --generate-policy --policy-output ./policy
terra self-test --generate-policy --validate-vm --policy-output ./vm-validated-policy
terra dev --generate-policy --policy-output ./dev-policy
terra ./dev.yaml --generate-policy --policy-output ./test-policy -- npm test
```

With self-test policy generation, `--validate-vm` additionally runs the full guest
feature suite under Bubblewrap using the same generated bundle; it requires
native Linux KVM and working Bubblewrap user namespaces. Release CI uses this
mode on each policy architecture. It fails instead of silently broadening a
policy when guest validation finds an uncovered operation.

For a box or recipe, `--generate-policy` selects foreground execution automatically
and requires a stopped box. An explicit `--foreground` is also accepted; `-d`
and already-running boxes are rejected before tracing.
Terra traces the selected VM workload and repeats it under enforcement. Recipe
paths, mounts, hooks, network settings, and commands after `--` follow ordinary
foreground execution. Relative recipe paths resolve against the shell's current
directory; `--project` selects the project's boxes. This mode requires native Linux KVM.

Policy generation executes the selected workload twice: once for tracing and
once under the generated policy. Custom workloads can repeat writes to box files,
host shares, and external services. Both passes use the same box and preserve its
files and configuration, so the second pass sees effects from the first.
Self-tests use private Terra state. `--policy-timeout` limits each generation
pass; `--help` shows its default. Policy options require `--generate-policy`.

Successful generation publishes a bundle beneath `./terra-seccomp`
(or `--policy-output`):

```text
supervisor.seccomp.json / supervisor.seccomp.bpf
vm.seccomp.json         / vm.seccomp.bpf
network.seccomp.json    / network.seccomp.bpf
manifest.json
```

The manifest records executable identity, role hashes and coverage, reviewed
supplements, and validation results. Test servers and launcher setup do not
supply VM network permissions. Missing role coverage fails generation. The
complete bundle must pass enforcement and negative boundary probes before
atomic publication. An existing real output directory is refused; published
outputs are symlinks to successful generations. Logs and traces remain in
`./terra-workload-logs` (or `--policy-diagnostics`). Generation does not install
the bundle. Select its directory with `vm.bwrap.policy`, or install the bundle
at `~/.terra/config/seccomp`.

Policies cover the observed paths and reviewed supplements for that binary and
architecture. Host-only enforcement does not certify a VM run; use
`self-test --generate-policy --validate-vm` for that assurance. No finite workload
covers every error or timing-dependent path. Regenerate after changing Terra or
the workload.

## Custom launcher contract

Set `vm.init` to one executable or script path. Relative paths resolve against
the directory containing `config.yaml`. The value is a path, not a shell command;
put any options in the launcher script. Terra invokes it with separate arguments:

```text
<init> --config <absolute-box-directory>/recipe.yaml
       --project <absolute-project-directory>
       --mode <create|run>
       -- <absolute-terra-executable> __vm <absolute-box-directory>
```

Spaces, quotes, Unicode and shell metacharacters in paths remain within their
own arguments. The launcher must execute the command after `--`, preserving its
standard input, inherited box lock descriptor or handle, environment, exit
status, termination, and readiness notification. On Unix, the box lock is FD 3.
The launcher must also preserve the inherited broker IPC endpoint (FD 7 on Unix).
Standard input carries the effective
boot plan; the launcher must leave it for `__vm`, not read it to infer mounts.
The boot plan is not passed in arguments. On Unix, a simple script can use
`exec` to replace itself with the chosen sandbox and VM process. On Windows, a
custom launcher must explicitly forward the inherited lock handle and its
environment metadata if it starts another process. Write launcher diagnostics
to standard error; Terra records them in the box's `launcher.log` and shows a
bounded tail when startup fails. Standard output is reserved for readiness.
Unix scripts need an executable interpreter line; Windows launchers follow
native executable or interpreter conventions.

`--config` names the box's pinned recipe, not the live project recipe or
`terra.yaml`. That file retains the original recipe YAML. Relative paths in it
resolve against `--project`, regardless of the launcher's working directory.
Terra writes `pinned-paths.yaml` beside `recipe.yaml` before starting the VM.
Its YAML shape is:

```yaml
mounts:
  - /canonical/host/share
env_file: /canonical/host/file
```

`mounts` is an ordered list of canonical host paths corresponding to the
recipe's `mounts` entries. `env_file` is a canonical host path or `null`.
Terra compares these targets with the paths currently resolved from the recipe
and requires another `terra setup` if they change. A custom launcher that reads
the recipe must use these pinned targets rather than follow a changed symlink.
In `create` mode, recipe shares are not granted to the VM, even if the recipe
lists mounts. In `run` mode, honor each mount's `readonly` grant. The command
after `--` receives the box directory, where Terra keeps its disk images,
volume images, sockets and logs.

A custom launcher is trusted host code. Terra cannot determine its containment
from a successful exit. A supervising launcher must keep the VM in its managed
process group or equivalent, so stop, failed-start cleanup, and foreground
parent death terminate the actual VM. Detached VMs must remain alive after the
starting CLI exits.

Custom launchers must keep the VM in the host PID namespace. Creating a PID
namespace is unsupported: the VM publishes its namespace-local PID, which
Terra cannot use to identify and force-stop the host process after graceful
shutdown fails. Use the built-in Bubblewrap launcher for PID isolation; it
provides the required host-PID handoff.
