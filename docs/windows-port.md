# Windows support

We want to support Windows while keeping Terrarium lean. Terrarium is built on
[libkrun](https://github.com/libkrun/libkrun), a strong and proven foundation
for running microVMs, so Windows support should follow libkrun rather than
requiring Terrarium to maintain a separate Windows VMM stack.

For now, Terrarium supports Linux and macOS. Windows is not supported because
the current libkrun does not support it, and Terrarium's host platform layer uses
Unix-only APIs.

## WSL2

Terrarium may run as a Linux program inside WSL2, not as a Windows binary. It
needs KVM exposed to the distribution:

```sh
test -r /dev/kvm && test -w /dev/kvm && echo "KVM ready"
```

[Current WSL2 enables nested virtualization by default](https://learn.microsoft.com/en-us/windows/wsl/wsl-config),
but the host CPU must support it. When Windows itself is a VM, the outer
hypervisor must expose virtualization extensions too. If WSL's
`nestedVirtualization` setting was disabled, set it to `true` in
`%UserProfile%\.wslconfig` and run `wsl --shutdown` before starting the
distribution again. WSL1 cannot run Terra because it has no Linux KVM device.

libkrun v2 plans to support Windows later. Once that support is available, we
will evaluate the smallest Terrarium changes needed to build and run on top of it.
The upstream work is tracked in [libkrun issue #798](https://github.com/libkrun/libkrun/issues/798).
