# VMM component

`terra-vmm-component` coordinates the VM's vCPUs and handles architecture-
specific exits. It resumes host-provided vCPU resources, services exits such as
MMIO and x86 port I/O, and reports VM lifecycle events.

The host grants VM and vCPU resources, lifecycle events and a narrow MMIO
client. The component has no direct guest-memory import. See [lib.rs](src/lib.rs),
[machine.rs](src/machine.rs), [lifecycle.rs](src/lifecycle.rs), and the
[authority inventory](../../docs/component-authority.md).
