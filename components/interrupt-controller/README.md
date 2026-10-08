# Interrupt controller component

`terra-interrupt-controller-component` models x86 IRQ-line delivery and the
IOAPIC register interface. The host configures device routes and the vCPU
count; the component returns value-based interrupt changes for native code to
validate and inject.

The component exports controller operations without host imports. See
[lib.rs](src/lib.rs), [interrupt-controller.wit](wit/interrupt-controller.wit),
and the [authority inventory](../../docs/component-authority.md).
