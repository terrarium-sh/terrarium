# Host VM launchers

Terra can start its host VM process directly, through a custom launcher, or
through its built-in Linux Bubblewrap launcher. Configure the choice globally in
`~/.terra/config.yaml`; a project recipe cannot change it. On Linux, an absent
or null `vm.init` selects Bubblewrap. On macOS and Windows it starts the VM
directly. A launcher that fails stops the launch.

```yaml
vm:
  init: direct
```

`vm.init: direct` opts out of the Linux Bubblewrap launcher. Terra embeds the
Bubblewrap executable and provides a built-in minimal seccomp policy on Linux.
To select a raw classic BPF policy explicitly:

```yaml
vm:
  init: bwrap
  bwrap:
    policy: /path/to/terra.seccomp.bpf
```

Policy selection has three steps:

1. Use `vm.bwrap.policy` when set. Relative paths resolve against `~/.terra`,
   the directory containing `config.yaml`.
2. Otherwise use `~/.terra/config/seccomp.bpf` if present.
3. Otherwise use the built-in minimal policy.

Terra never downloads policies or searches beside the executable. Both file
options require regular files containing raw classic BPF, with no YAML envelope
or Base64. A missing explicit file or an invalid selected file fails startup;
Terra never silently replaces it with the built-in policy. Terra checks the file
size and instruction alignment, and the kernel validates the filter when
Bubblewrap installs it.
Operators must choose a policy appropriate for their host architecture and
Terra binary. Regenerate and validate generated filters after changing the
executable; older filters may omit required network syscalls now that socket
operations run in the jailed VM process.

The built-in policy is compiled for the target architecture and embedded during
the Cargo build, including CI builds. Boot loads those bytes without generating
a filter. The policy allows ordinary syscalls and returns `EPERM` for ptrace,
BPF, performance monitoring, kernel/module loading, reboot, and kernel keyring
operations. Alternate syscall ABIs are killed. This denylist is less restrictive
than the generated syscall/ioctl allowlist; Bubblewrap's filesystem, namespace,
and capability restrictions still apply. The jail shares the host network
namespace.

To require a policy file and refuse the built-in policy, set:

```yaml
vm:
  init: bwrap
  bwrap:
    allow_fallback: false
```

`allow_fallback` defaults to `true`. With `false`, either the explicit file or
`~/.terra/config/seccomp.bpf` must be present. This setting does not assess the
selected policy's restrictiveness. Policy compilation and generation remain
build-time tasks; runtime hosts do not need a policy compiler.

Bubblewrap settings are unused when `vm.init` selects another launcher.
Terra refuses a configured launcher or selected local policy inside a
guest-writable share or writable Terra box state, so a guest cannot replace
an asset used for a later boot.

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

## Built-in Linux boundary

The embedded Bubblewrap launcher uses a restricted mount view, user, mount,
IPC, UTS, and PID namespaces, drops capabilities, and installs the selected
seccomp filter before starting the VM. It grants the selected box's required
files, approved run-mode shares, and `/dev/kvm`. The VM shares the host network
namespace. Its network component and policy-enforcing socket hosts run inside
the jailed VM process.

The built-in launcher clears the inherited host environment and forwards only
`RUST_LOG` and `TERRA_BOOT_TRACE` for diagnostics. Recipe guest environment
grants are carried separately in the boot plan.

Bubblewrap's PID namespace gives the VM a different PID from its host PID.
Terra's parent records the host PID and start identity in the box's `host.pid`
before sending the boot plan. That file is read-only inside the jail, so a
compromised native VM process cannot rewrite the signal target used by `stop`.
The inherited FD 3 remains the cooperative box run lock; it is not a defense
against native code deliberately unlocking or disrupting its own box.

Recipe network policies remain enforced at the component boundary, but native
VM-process compromise can bypass them and reach host-network services while
remaining subject to the jail's other restrictions. See
[network policy limits](security.md#network-policy-limits) for indirect escape
risks and independent host controls. Native KVM tests under the enforced
launcher are required to validate containment on each architecture.
Bubblewrap does not supply cgroups or a hard CPU, memory, disk, or bandwidth
quota. The built-in launcher targets the statically linked Linux musl release executable; custom launchers can supply a
different host layout.
